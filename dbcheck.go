package dbcheck

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/coredns/coredns/middleware"
	// "github.com/coredns/coredns/middleware/pkg/dnsutil"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"golang.org/x/net/context"

	_ "github.com/lib/pq"
)

type DbCheck struct {
	Next middleware.Handler

	Database         string
	ConnectionString string
	Fallthrough      bool

	db *sql.DB
}

type Zone struct {
	id   int64
	name string
}

func (check *DbCheck) Init() error {
	if check.Database != "" {
		fmt.Printf("Connecting to database %s %s\n", check.Database, check.ConnectionString)

		con, err := sql.Open(check.Database, check.ConnectionString)

		check.db = con

		if check.db != nil {
			fmt.Printf("Initialized database!")
		}

		if err != nil {
			fmt.Printf("Error while connecting to database: %s", err)
			return err
		}
	}

	return nil
}

func (check *DbCheck) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var rr dns.RR

	state := request.Request{W: w, Req: r}

	if check.db == nil {
		return check.failOrFallthrough(ctx, w, r, middleware.Error(check.Name(), errors.New("No db connection initialized")))
	}

	if state.QClass() != dns.ClassINET {
		return check.failOrFallthrough(ctx, w, r, middleware.Error(check.Name(), errors.New("can only deal with ClassINET")))
	}

	qname := state.Name()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative, m.RecursionAvailable, m.Compress = true, true, true

	/* Explicit support for
	NS
	SOA
	MX
	A
	AAAA
	PTR
	CNAME
	TXT
	SRV
	*/

	// TODO multiple answers

	qnames := dns.SplitDomainName(qname)

	param_names := make([]string, len(qnames))
	params := make([]interface{}, len(qnames))

	for i := range qnames {
		param_names[i] = "$" + strconv.Itoa(i+1)
		params[i] = strings.Join(qnames[i:], ".") + "."
	}

	// find most matching zone name in sql:
	sql := "SELECT id, name FROM zones WHERE deleted_at is null and disabled = false and name in (" + strings.Join(param_names, ",") + ") ORDER BY length(name) DESC"

	// check for zone with that name
	zones, err := check.db.Query(sql, params...)

	if err != nil {
		fmt.Printf("Error occured when looking up zone: %s\n", err)

		return check.failOrFallthrough(ctx, w, r, middleware.Error(check.Name(), errors.New("Error occured when looking up zone")))
	}

	defer zones.Close()

	// handle each zone that matched,
	// until we find the first record
	// longest match first
	for zones.Next() {
		zone := Zone{}
		err := zones.Scan(&zone.id, &zone.name)

		if err != nil {
			fmt.Printf("Error while scanning row: %s\n", err)
			break
		}

		fmt.Printf("Checking Zone: %d %s\n", zone.id, zone.name)

		var rrs []interface{}

		// check for the first record of this type
		rrs, err = check.findFirstRecord(state, zone, qname)

		if rrs == nil && err == nil {
			switch state.QType() {
			case dns.TypeA:
				// Try to match wildcard
				rrs, err = check.findFirstRecord(state, zone, "*."+strings.Join(qnames[1:], "."))
			}
		}

		if err != nil {
			fmt.Printf("Error occured when looking up records for zone: %s\n", err)
		}

		if rrs != nil && len(rrs) > 0 {
			rr = rrs[0].(dns.RR)
			break
		}
	}

	if rr != nil {
		m.Answer = append(m.Answer, rr)
		state.SizeAndDo(m)
		w.WriteMsg(m)

		return dns.RcodeSuccess, nil
	}

	return check.failOrFallthrough(ctx, w, r, nil)
}

func (check *DbCheck) failOrFallthrough(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, err error) (int, error) {
	if check.Fallthrough {
		return middleware.NextOrFailure(check.Name(), check.Next, ctx, w, r)
	}

	return dns.RcodeServerFailure, err
}

func (check *DbCheck) findFirstRecord(state request.Request, zone Zone, qname string) ([]interface{}, error) {
	qnames := dns.SplitDomainName(qname)
	params_a := make([]interface{}, 2)
	params_a[0] = zone.id

	if zone.name == qname {
		params_a[1] = "@"
	} else {
		params_a[1] = qnames[0]
	}

	records, err := check.db.Query("SELECT id, name, ttl, "+mapTypeToFields(state.QType())+" FROM "+mapTypeToTable(state.QType())+" WHERE deleted_at is null and disabled = false and zone_id = $1 and name = $2", params_a...)

	if err != nil {
		fmt.Printf("Error occured when looking ip "+mapTypeToTable(state.QType())+" %s\n", err)
		return nil, err
	}

	defer records.Close()

	for records.Next() {
		rr, err := mapFieldToRecords(state, zone, records)

		if err != nil {
			return nil, err
		}

		fmt.Printf("Found record %+#v\n", rr)

		return []interface{}{rr}, nil
	}

	return nil, nil
}

func mapFieldToRecords(state request.Request, zone Zone, records *sql.Rows) (interface{}, error) {
	switch state.QType() {
	case dns.TypeA:
		var id, ttl int64
		var name, addr string
		records.Scan(&id, &name, &ttl, &addr)

		ip := net.ParseIP(addr)

		if ip != nil {
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(ttl)},
				A:   ip,
			}

			return rr, nil
		}
	case dns.TypeAAAA:
		var id, ttl int64
		var name, addr string
		records.Scan(&id, &name, &ttl, &addr)

		ip := net.ParseIP(addr)

		if ip != nil {
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(ttl)},
				AAAA: ip,
			}

			return rr, nil
		}
	case dns.TypePTR:
		var id, ttl int64
		var name, ptr string
		records.Scan(&id, &name, &ttl, &ptr)

		// append the zone name
		if ptr[len(ptr)-1] != '.' {
			ptr = ptr + zone.name
		}

		rr := &dns.PTR{
			Hdr: dns.RR_Header{Name: state.QName(), Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: uint32(ttl)},
			Ptr: ptr,
		}

		return rr, nil
	}

	return nil, nil
}

func mapTypeToTable(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "a_records"
	case dns.TypeAAAA:
		return "aaaa_records"
	case dns.TypeMX:
		return "mx_records"
	case dns.TypePTR:
		return "ptr_records"
	case dns.TypeNS:
		return "ns_records"
	case dns.TypeTXT:
		return "txt_records"
	case dns.TypeSOA:
		return "soa_records"
	case dns.TypeSRV:
		return "srv_records"
	case dns.TypeCNAME:
		return "cname_records"
	}

	return ""
}

func mapTypeToFields(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "a"
	case dns.TypeAAAA:
		return "aaaa"
	case dns.TypeMX:
		return "preference, mx"
	case dns.TypePTR:
		return "ptr"
	case dns.TypeNS:
		return "ns"
	case dns.TypeTXT:
		return "txt"
	case dns.TypeSOA:
		return "ns, mbox, serial, refresh, retry, expire, minttl"
	case dns.TypeSRV:
		return "priority, weight, port, target"
	case dns.TypeCNAME:
		return "target"
	}

	return ""
}

func (check *DbCheck) Name() string {
	return "dbcheck"
}
