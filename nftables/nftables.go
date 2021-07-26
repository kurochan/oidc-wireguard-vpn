package nftables

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"go.uber.org/zap"
)

type Config struct {
	TableName        string
	VPNInterfaceName string
	VPNInterfaceIP   net.IPNet
	NATEnabled       bool
}

type Nftables struct {
	Config   Config
	TestDial func([]netlink.Message) ([]netlink.Message, error)
}

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, []byte(n+"\x00"))
	return b
}

func getStartIP(ipNet net.IPNet) net.IP {
	ip := ipNet.IP
	mask := ipNet.Mask
	return ip.Mask(mask)
}

// only support IPv4
func getEndIP(ipNet net.IPNet) net.IP {
	ip := ipNet.IP
	mask := ipNet.Mask
	n := len(ip)
	if n != len(mask) {
		return nil
	}
	out := make(net.IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] | (mask[i] ^ 0xff)
	}
	return out
}

func (n *Nftables) AddAllowedIP(ip net.IP) error {
	if len(ip) != 4 {
		zap.L().Error("only support IPv4 address")
		return errors.New("only support IPv4 address")
	}

	connection := &nftables.Conn{
		TestDial: n.TestDial,
	}

	table := connection.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   n.Config.TableName,
	})

	allowedIPv4 := &nftables.Set{
		Table:   table,
		Name:    "allowed-ips-v4",
		KeyType: nftables.TypeIPAddr,
	}
	if err := connection.AddSet(allowedIPv4, []nftables.SetElement{{Key: []byte(ip)}}); err != nil {
		zap.L().Error("failed to add allowed ip address", zap.Error(err))
		return err
	}
	if err := connection.Flush(); err != nil {
		zap.L().Error("failed to flush nftables", zap.Error(err))
		return err
	}
	zap.L().Info(fmt.Sprintf("add allowed ip address to %s", ip.String()))

	return nil
}

func (n *Nftables) DeleteAllowedIP(ip net.IP) error {
	if len(ip) != 4 {
		zap.L().Error("only support IPv4 address")
		return errors.New("only support IPv4 address")
	}

	connection := &nftables.Conn{
		TestDial: n.TestDial,
	}

	table := connection.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   n.Config.TableName,
	})

	allowedIPv4 := &nftables.Set{
		Table:   table,
		Name:    "allowed-ips-v4",
		KeyType: nftables.TypeIPAddr,
	}
	if err := connection.SetDeleteElements(allowedIPv4, []nftables.SetElement{{Key: []byte(ip)}}); err != nil {
		zap.L().Error("failed to delete allowed ip address", zap.Error(err))
		return err
	}
	if err := connection.Flush(); err != nil {
		zap.L().Error("failed to update nftables", zap.Error(err))
		return err
	}
	zap.L().Info(fmt.Sprintf("delete allowed ip address to %s", ip.String()))

	return nil
}

func (n *Nftables) addTable(connection *nftables.Conn) (*nftables.Table, error) {
	table := connection.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   n.Config.TableName,
	})
	connection.DelTable(table)
	table = connection.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   n.Config.TableName,
	})
	if err := connection.Flush(); err != nil {
		zap.L().Error("failed to initialize nftables", zap.Error(err))
		return nil, err
	}

	return table, nil
}

func (n *Nftables) addAllowedIPSet(connection *nftables.Conn, table *nftables.Table) (*nftables.Set, error) {
	allowedIPv4 := &nftables.Set{
		Table:   table,
		Name:    "allowed-ips-v4",
		KeyType: nftables.TypeIPAddr,
	}
	if err := connection.AddSet(allowedIPv4, []nftables.SetElement{}); err != nil {
		zap.L().Error("failed to add allowed ip address", zap.Error(err))
		return nil, err
	}

	return allowedIPv4, nil
}

func (n *Nftables) addFilterRule(connection *nftables.Conn, table *nftables.Table, allowedIPv4 *nftables.Set) error {
	defaultAccept := nftables.ChainPolicyAccept
	vpn := connection.AddChain(&nftables.Chain{
		Name:     "vpn-filter-rule",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &defaultAccept,
	})
	connection.AddRule(&nftables.Rule{
		Table: table,
		Chain: vpn,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     ifname(n.Config.VPNInterfaceName),
			},
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				Invert:         true,
				SetID:          allowedIPv4.ID,
				SetName:        allowedIPv4.Name,
			},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	return nil
}

func (n *Nftables) addNatRule(connection *nftables.Conn, table *nftables.Table) error {
	if len(n.Config.VPNInterfaceIP.IP) != 4 {
		zap.L().Error("only support IPv4 address")
		return errors.New("only support IPv4 address")
	}

	defaultAccept := nftables.ChainPolicyAccept
	nat := connection.AddChain(&nftables.Chain{
		Name:     "nat-rule",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   &defaultAccept,
	})

	connection.AddRule(&nftables.Rule{
		Table: table,
		Chain: nat,
		Exprs: []expr.Any{
			// [ payload load 4b @ network header + 12 => reg 1 ]
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Range{
				Op:       expr.CmpOpEq,
				Register: 1,
				FromData: getStartIP(n.Config.VPNInterfaceIP),
				ToData:   getEndIP(n.Config.VPNInterfaceIP),
			},
			&expr.Masq{},
		},
	})

	return nil
}

func (n *Nftables) InitNftable() error {
	connection := &nftables.Conn{
		TestDial: n.TestDial,
	}

	table, err := n.addTable(connection)
	if err != nil {
		return err
	}
	allowedIPv4, err := n.addAllowedIPSet(connection, table)
	if err != nil {
		return err
	}
	err = n.addFilterRule(connection, table, allowedIPv4) // Drop NOT allowed IPs rule
	if err != nil {
		return err
	}
	if n.Config.NATEnabled {
		if err := n.addNatRule(connection, table); err != nil {
			return err
		}
	}

	if err := connection.Flush(); err != nil {
		zap.L().Error("failed to add rules to nftables", zap.Error(err))
		return err
	}
	return nil
}

func (n *Nftables) DeleteNfTable() error {
	connection := &nftables.Conn{
		TestDial: n.TestDial,
	}

	table := connection.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   n.Config.TableName,
	})
	connection.DelTable(table)
	if err := connection.Flush(); err != nil {
		zap.L().Error("failed to delete nftables", zap.Error(err))
		return err
	}
	return nil
}
