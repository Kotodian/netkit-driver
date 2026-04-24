//go:build linux

package netkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"

	"github.com/containerd/log"
	"github.com/moby/moby/v2/daemon/libnetwork/datastore"
	"github.com/moby/moby/v2/daemon/libnetwork/drivers/bridge"
	"github.com/moby/moby/v2/daemon/libnetwork/netlabel"
	"github.com/moby/moby/v2/daemon/libnetwork/portmapperapi"
	"github.com/moby/moby/v2/daemon/libnetwork/types"
)

const (
	netkitPrefix         = "netkit"
	netkitNetworkPrefix  = netkitPrefix + "/network"
	netkitEndpointPrefix = netkitPrefix + "/endpoint"
)

type configuration struct {
	ID                 string
	dbIndex            uint64
	dbExists           bool
	Internal           bool
	Parent             string
	EnableIPMasquerade bool
	EnableBigTCP       bool
	GwModeIPv4         gwMode
	GwModeIPv6         gwMode
	HostIPv4           net.IP
	HostIPv6           net.IP
	Ipv4Subnets        []*ipSubnet
	Ipv6Subnets        []*ipSubnet
}

type ipSubnet struct {
	SubnetIP string
	GwIP     string
}

func (d *driver) initStore() error {
	if err := d.populateNetworks(); err != nil {
		return err
	}
	return d.populateEndpoints()
}

func (d *driver) populateNetworks() error {
	kvol, err := d.store.List(&configuration{})
	if err != nil && !errors.Is(err, datastore.ErrKeyNotFound) {
		return fmt.Errorf("failed to get netkit network configurations from store: %w", err)
	}
	if errors.Is(err, datastore.ErrKeyNotFound) {
		return nil
	}

	for _, kvo := range kvol {
		config := kvo.(*configuration)
		if _, err = d.createNetwork(config); err != nil {
			log.G(context.TODO()).Warnf("could not create netkit network for id %s from persistent state", config.ID)
		}
	}

	return nil
}

func (d *driver) populateEndpoints() error {
	kvol, err := d.store.List(&endpoint{})
	if err != nil && !errors.Is(err, datastore.ErrKeyNotFound) {
		return fmt.Errorf("failed to get netkit endpoints from store: %w", err)
	}
	if errors.Is(err, datastore.ErrKeyNotFound) {
		return nil
	}

	for _, kvo := range kvol {
		ep := kvo.(*endpoint)
		n, ok := d.networks[ep.nid]
		if !ok {
			log.G(context.TODO()).Debugf("network (%.7s) not found for restored netkit endpoint (%.7s)", ep.nid, ep.id)
			if err := d.storeDelete(ep); err != nil {
				log.G(context.TODO()).Debugf("failed to delete stale netkit endpoint (%.7s) from store", ep.id)
			}
			continue
		}
		n.endpoints[ep.id] = ep
		if err := d.upsertEgressEndpointDatapath(context.TODO(), n, ep); err != nil {
			log.G(context.TODO()).WithFields(log.Fields{
				"error": err,
				"ep.id": ep.id,
				"nid":   ep.nid,
			}).Warn("Failed to restore netkit egress datapath")
		}
		if err := d.restorePublishedPorts(context.TODO(), ep); err != nil {
			log.G(context.TODO()).WithFields(log.Fields{
				"error": err,
				"ep.id": ep.id,
				"nid":   ep.nid,
			}).Warn("Failed to restore netkit published ports")
		}
		if err := d.attachEndpointDatapath(context.TODO(), ep); err != nil {
			log.G(context.TODO()).WithFields(log.Fields{
				"error": err,
				"ep.id": ep.id,
				"nid":   ep.nid,
			}).Warn("Failed to attach netkit endpoint datapath during restore")
		}
		if err := d.upsertLocalEndpointDatapaths(ep); err != nil {
			log.G(context.TODO()).WithFields(log.Fields{
				"error": err,
				"ep.id": ep.id,
				"nid":   ep.nid,
			}).Warn("Failed to restore netkit local endpoint datapath")
		}
	}

	return nil
}

func (d *driver) restorePublishedPorts(ctx context.Context, ep *endpoint) error {
	if ep == nil || len(ep.portMapping) == 0 {
		return nil
	}

	n, ok := d.networks[ep.nid]
	if !ok {
		return nil
	}

	scope := publishedPortScopeKey(n)
	if scope == "" {
		return nil
	}

	mode := restoredPortBindingMode(ep)
	reqs := restoredPortBindingReqs(ep.portMapping)

	d.configNetwork.Lock()
	defer d.configNetwork.Unlock()

	rt, err := d.acquireParentRuntimeLocked(ctx, scope)
	if err != nil {
		return err
	}

	releaseRuntime := true
	defer func() {
		if releaseRuntime {
			_ = d.releaseParentRuntimeLocked(context.TODO(), scope)
		}
	}()

	if err := rt.AddEndpoint(ctx, publishedEndpointConfigForEndpoint(ep)); err != nil {
		return err
	}

	restoreSucceeded := false
	defer func() {
		if !restoreSucceeded {
			_ = rt.DelEndpoint(context.TODO(), publishedEndpointConfigForEndpoint(ep))
		}
	}()

	portMapping, err := rt.ReconcilePortBindings(ctx, publishedPortRequest{
		Addr:           ep.addr,
		Addrv6:         ep.addrv6,
		PortBindings:   reqs,
		DesiredMode:    mode,
		DisableNATIPv4: n.config.GwModeIPv4.routed(),
		DisableNATIPv6: n.config.GwModeIPv6.routed(),
	})
	if err != nil {
		return err
	}

	ep.portMapping = portMapping
	ep.portBindingState = mode
	ep.publishedParent = scope
	restoreSucceeded = true
	releaseRuntime = false
	return nil
}

func restoredPortBindingMode(ep *endpoint) portBindingMode {
	mode := ep.portBindingState
	if len(ep.portMapping) == 0 {
		return mode
	}

	mode.routed = true
	for _, pb := range ep.portMapping {
		if pb.HostIP.To4() != nil {
			mode.ipv4 = true
			continue
		}
		mode.ipv6 = true
	}
	return mode
}

func restoredPortBindingReqs(bindings []portmapperapi.PortBinding) []portmapperapi.PortBindingReq {
	reqs := make([]portmapperapi.PortBindingReq, 0, len(bindings))
	for _, pb := range bindings {
		req := portmapperapi.PortBindingReq{
			PortBinding: pb.Copy(),
			Mapper:      pb.Mapper,
		}
		req.HostPortEnd = req.HostPort
		reqs = append(reqs, req)
	}
	return reqs
}

func (d *driver) storeUpdate(kvObject datastore.KVObject) error {
	if d.store == nil {
		log.G(context.TODO()).Warnf("netkit store not initialized. kv object %s is not added to the store", datastore.Key(kvObject.Key()...))
		return nil
	}
	if err := d.store.PutObjectAtomic(kvObject); err != nil {
		return fmt.Errorf("failed to update netkit store for object type %T: %v", kvObject, err)
	}
	return nil
}

func (d *driver) storeDelete(kvObject datastore.KVObject) error {
	if d.store == nil {
		log.G(context.TODO()).Debugf("netkit store not initialized. kv object %s is not deleted from store", datastore.Key(kvObject.Key()...))
		return nil
	}
	return d.store.DeleteObject(kvObject)
}

func (config *configuration) MarshalJSON() ([]byte, error) {
	nMap := map[string]any{
		"ID":                 config.ID,
		"Parent":             config.Parent,
		"Internal":           config.Internal,
		"EnableIPMasquerade": config.EnableIPMasquerade,
		"EnableBigTCP":       config.EnableBigTCP,
		"GwModeIPv4":         config.GwModeIPv4,
		"GwModeIPv6":         config.GwModeIPv6,
		"HostIPv4":           config.HostIPv4.String(),
		"HostIPv6":           config.HostIPv6.String(),
	}
	if len(config.Ipv4Subnets) > 0 {
		data, err := json.Marshal(config.Ipv4Subnets)
		if err != nil {
			return nil, err
		}
		nMap["Ipv4Subnets"] = string(data)
	}
	if len(config.Ipv6Subnets) > 0 {
		data, err := json.Marshal(config.Ipv6Subnets)
		if err != nil {
			return nil, err
		}
		nMap["Ipv6Subnets"] = string(data)
	}
	return json.Marshal(nMap)
}

func (config *configuration) UnmarshalJSON(b []byte) error {
	var nMap map[string]any
	if err := json.Unmarshal(b, &nMap); err != nil {
		return err
	}

	config.EnableBigTCP = true
	config.ID = nMap["ID"].(string)
	if v, ok := nMap["Parent"]; ok {
		config.Parent, _ = v.(string)
	}
	config.Internal = nMap["Internal"].(bool)
	if v, ok := nMap["EnableIPMasquerade"]; ok {
		config.EnableIPMasquerade = v.(bool)
	}
	if v, ok := nMap["EnableBigTCP"]; ok {
		config.EnableBigTCP = v.(bool)
	}
	if v, ok := nMap["GwModeIPv4"]; ok {
		config.GwModeIPv4, _ = newGwMode(v.(string))
	}
	if v, ok := nMap["GwModeIPv6"]; ok {
		config.GwModeIPv6, _ = newGwMode(v.(string))
	}
	if v, ok := nMap["HostIPv4"]; ok {
		config.HostIPv4 = net.ParseIP(v.(string))
	}
	if v, ok := nMap["HostIPv6"]; ok {
		config.HostIPv6 = net.ParseIP(v.(string))
	}

	if v, ok := nMap["Ipv4Subnets"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &config.Ipv4Subnets); err != nil {
			return err
		}
	}
	if v, ok := nMap["Ipv6Subnets"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &config.Ipv6Subnets); err != nil {
			return err
		}
	}
	return nil
}

func defaultConfiguration() *configuration {
	return &configuration{
		EnableIPMasquerade: true,
		EnableBigTCP:       true,
		GwModeIPv4:         gwModeNAT,
		GwModeIPv6:         gwModeNAT,
	}
}

func (c *configuration) applyBridgeLabel(label, value string) error {
	switch label {
	case bridge.EnableIPMasquerade:
		switch value {
		case "true":
			c.EnableIPMasquerade = true
		case "false":
			c.EnableIPMasquerade = false
		default:
			return types.InvalidParameterErrorf("invalid value for %s: %s", bridge.EnableIPMasquerade, value)
		}
	case bigTCPOpt:
		switch value {
		case "true":
			c.EnableBigTCP = true
		case "false":
			c.EnableBigTCP = false
		default:
			return types.InvalidParameterErrorf("invalid value for %s: %s", bigTCPOpt, value)
		}
	case bridge.IPv4GatewayMode:
		mode, err := newGwMode(value)
		if err != nil {
			return err
		}
		c.GwModeIPv4 = mode
	case bridge.IPv6GatewayMode:
		mode, err := newGwMode(value)
		if err != nil {
			return err
		}
		c.GwModeIPv6 = mode
	case netlabel.HostIPv4:
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return types.InvalidParameterErrorf("invalid value for %s: %s", netlabel.HostIPv4, value)
		}
		c.HostIPv4 = ip.To4()
	case netlabel.HostIPv6:
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil {
			return types.InvalidParameterErrorf("invalid value for %s: %s", netlabel.HostIPv6, value)
		}
		c.HostIPv6 = ip
	}
	return nil
}

func (config *configuration) Key() []string {
	return []string{netkitNetworkPrefix, config.ID}
}

func (config *configuration) KeyPrefix() []string {
	return []string{netkitNetworkPrefix}
}

func (config *configuration) Value() []byte {
	b, err := json.Marshal(config)
	if err != nil {
		return nil
	}
	return b
}

func (config *configuration) SetValue(value []byte) error {
	return json.Unmarshal(value, config)
}

func (config *configuration) Index() uint64 {
	return config.dbIndex
}

func (config *configuration) SetIndex(index uint64) {
	config.dbIndex = index
	config.dbExists = true
}

func (config *configuration) Exists() bool {
	return config.dbExists
}

func (config *configuration) Skip() bool {
	return false
}

func (config *configuration) New() datastore.KVObject {
	return &configuration{}
}

func (config *configuration) CopyTo(o datastore.KVObject) error {
	dst := o.(*configuration)
	*dst = *config
	return nil
}

func (ep *endpoint) MarshalJSON() ([]byte, error) {
	epMap := map[string]any{
		"id":      ep.id,
		"nid":     ep.nid,
		"SrcName": ep.srcName,
		"HostIf":  ep.hostIf,
	}
	if len(ep.mac) != 0 {
		epMap["MacAddress"] = ep.mac.String()
	}
	if ep.addr != nil {
		epMap["Addr"] = ep.addr.String()
	}
	if ep.addrv6 != nil {
		epMap["Addrv6"] = ep.addrv6.String()
	}
	if ep.extConnConfig != nil {
		data, err := json.Marshal(ep.extConnConfig)
		if err != nil {
			return nil, err
		}
		epMap["ExternalConnConfig"] = string(data)
	}
	if len(ep.portMapping) != 0 {
		data, err := json.Marshal(ep.portMapping)
		if err != nil {
			return nil, err
		}
		epMap["PortMapping"] = string(data)
	}
	if ep.publishedParent != "" {
		epMap["PublishedParent"] = ep.publishedParent
	}
	if ep.portBindingState != (portBindingMode{}) {
		epMap["PortBindingState"] = map[string]bool{
			"routed": ep.portBindingState.routed,
			"ipv4":   ep.portBindingState.ipv4,
			"ipv6":   ep.portBindingState.ipv6,
		}
	}
	return json.Marshal(epMap)
}

func (ep *endpoint) UnmarshalJSON(b []byte) error {
	var (
		epMap map[string]any
		err   error
	)
	if err = json.Unmarshal(b, &epMap); err != nil {
		return fmt.Errorf("failed to unmarshal netkit endpoint: %v", err)
	}

	if v, ok := epMap["MacAddress"]; ok {
		if ep.mac, err = net.ParseMAC(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode netkit endpoint MAC address (%s): %v", v.(string), err)
		}
	}
	if v, ok := epMap["Addr"]; ok {
		if ep.addr, err = types.ParseCIDR(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode netkit endpoint IPv4 address (%s): %v", v.(string), err)
		}
	}
	if v, ok := epMap["Addrv6"]; ok {
		if ep.addrv6, err = types.ParseCIDR(v.(string)); err != nil {
			return types.InternalErrorf("failed to decode netkit endpoint IPv6 address (%s): %v", v.(string), err)
		}
	}
	if v, ok := epMap["ExternalConnConfig"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &ep.extConnConfig); err != nil {
			return fmt.Errorf("failed to decode netkit endpoint external connectivity config: %w", err)
		}
	}
	if v, ok := epMap["PortMapping"]; ok {
		if err := json.Unmarshal([]byte(v.(string)), &ep.portMapping); err != nil {
			return fmt.Errorf("failed to decode netkit endpoint port mapping: %w", err)
		}
		for i := range ep.portMapping {
			ep.portMapping[i].HostPortEnd = ep.portMapping[i].HostPort
		}
	}
	if v, ok := epMap["PublishedParent"]; ok {
		ep.publishedParent = v.(string)
	}
	if v, ok := epMap["PortBindingState"]; ok {
		state, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("failed to decode netkit endpoint port binding state")
		}
		ep.portBindingState = portBindingMode{
			routed: boolValue(state["routed"]),
			ipv4:   boolValue(state["ipv4"]),
			ipv6:   boolValue(state["ipv6"]),
		}
	}

	ep.id = epMap["id"].(string)
	ep.nid = epMap["nid"].(string)
	ep.srcName = epMap["SrcName"].(string)
	if v, ok := epMap["HostIf"]; ok {
		ep.hostIf, _ = v.(string)
	}
	return nil
}

func boolValue(v any) bool {
	b, _ := v.(bool)
	return b
}

func (ep *endpoint) Key() []string {
	return []string{netkitEndpointPrefix, ep.id}
}

func (ep *endpoint) KeyPrefix() []string {
	return []string{netkitEndpointPrefix}
}

func (ep *endpoint) Value() []byte {
	b, err := json.Marshal(ep)
	if err != nil {
		return nil
	}
	return b
}

func (ep *endpoint) SetValue(value []byte) error {
	return json.Unmarshal(value, ep)
}

func (ep *endpoint) Index() uint64 {
	return ep.dbIndex
}

func (ep *endpoint) SetIndex(index uint64) {
	ep.dbIndex = index
	ep.dbExists = true
}

func (ep *endpoint) Exists() bool {
	return ep.dbExists
}

func (ep *endpoint) Skip() bool {
	return false
}

func (ep *endpoint) New() datastore.KVObject {
	return &endpoint{}
}

func (ep *endpoint) CopyTo(o datastore.KVObject) error {
	dst := o.(*endpoint)
	*dst = *ep
	return nil
}
