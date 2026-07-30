package identify

import (
	"strings"

	"Tarsier/internal/eve"
)

// Handlers for every Suricata event type that says something about a device.
//
// Field paths are read defensively throughout. Names have moved between
// Suricata versions and distributions patch independently, so anything that
// might have relocated is looked up via FirstStr against every known spelling,
// and a missing field is always "this build does not emit that" rather than an
// error.

// --- identity --------------------------------------------------------------

// addDHCP is the highest-value handler. A device joining the network announces
// its hostname, its MAC and frequently its vendor and OS, unprompted.
func (r *Resolver) addDHCP(rec *eve.Record) {
	ip := rec.FirstStr("dhcp.assigned_ip", "dhcp.client_ip")
	if ip == "" || ip == "0.0.0.0" {
		ip = rec.Str("src_ip")
	}
	if !isPrivate(ip) {
		return
	}
	d := r.device(ip)

	if mac := rec.Str("dhcp.client_mac"); mac != "" {
		r.applyMAC(d, mac)
	}
	if host := rec.Str("dhcp.hostname"); host != "" {
		d.addHostname(host)
		applySubstringRules(d, "dhcp.hostname", host, hostnamePrefixes)
	}
	// Spelling differs across Suricata versions.
	if vc := rec.FirstStr("dhcp.vendor_class_identifier", "dhcp.vendor_class"); vc != "" {
		applySubstringRules(d, "dhcp.vendor_class", vc, dhcpVendorClass)
		applySubstringRules(d, "dhcp.vendor_class", vc, dhcpVendorClassSecondary)
	}
}

// addARP closes the biggest blind spot in passive discovery.
//
// DHCP only reveals devices that ask for an address. Servers, printers, cameras
// and PLCs are routinely configured statically and never appear in it. ARP sees
// every device on the segment regardless, so this is what makes the inventory
// actually complete. Requires Suricata 8.0 or later.
func (r *Resolver) addARP(rec *eve.Record) {
	pairs := [][2]string{
		{rec.FirstStr("arp.src_ip", "arp.sender_ip"), rec.FirstStr("arp.src_mac", "arp.sender_mac")},
		{rec.FirstStr("arp.dest_ip", "arp.target_ip"), rec.FirstStr("arp.dest_mac", "arp.target_mac")},
	}
	for _, p := range pairs {
		ip, mac := p[0], p[1]
		if !isPrivate(ip) || mac == "" || strings.HasPrefix(mac, "00:00:00:00:00:00") {
			continue
		}
		r.applyMAC(r.device(ip), mac)
	}
}

// applyMAC records a hardware address and everything its OUI implies.
func (r *Resolver) applyMAC(d *Device, mac string) {
	if d == nil || mac == "" {
		return
	}
	d.MAC = strings.ToLower(mac)
	vendor := lookupOUI(mac)
	if vendor == "" {
		return
	}
	d.Vendor = vendor
	d.note("mac.oui", mac, "vendor="+vendor, 0.85)
	if cls, ok := ouiClass[vendor]; ok {
		d.note("mac.oui", mac, "class="+string(cls), 0.7)
	}
}

// addDNS harvests names for local addresses from A-record answers, which is how
// mDNS and internal DNS reveal friendly device names. Also flags DNS-over-HTTPS,
// which is worth knowing about because it bypasses local DNS controls.
func (r *Resolver) addDNS(rec *eve.Record, eventType string) {
	if eventType == "doh2" {
		if src := rec.Str("src_ip"); isPrivate(src) {
			d := r.device(src)
			d.Protocols["dns-over-https"] = true
			r.addFinding(Finding{
				Severity: SevLow, Kind: "dns-over-https", Device: src,
				Title:  "Device is using DNS-over-HTTPS",
				Detail: "This device is resolving names through an encrypted service outside your network, so your own DNS filtering and logging no longer see what it looks up.",
				Fix:    "If you rely on DNS filtering, turn DoH off in the browser via policy (Chrome and Edge both have a Group Policy setting; Firefox has network.trrs.mode) and block known DoH resolvers at the firewall.",
			})
		}
		return
	}

	name := rec.Str("dns.rrname")
	// Flat form (Suricata 6.x and answers in 7.x+).
	if rdata := rec.Str("dns.rdata"); isPrivate(rdata) && name != "" {
		d := r.device(rdata)
		d.addHostname(name)
		applySubstringRules(d, "dns.name", name, hostnamePrefixes)
	}
	// Array form.
	if answers, ok := rec.Get("dns.answers").([]any); ok {
		for _, a := range answers {
			m, ok := a.(map[string]any)
			if !ok {
				continue
			}
			rdata, _ := m["rdata"].(string)
			rrname, _ := m["rrname"].(string)
			if isPrivate(rdata) && rrname != "" {
				d := r.device(rdata)
				d.addHostname(rrname)
				applySubstringRules(d, "dns.name", rrname, hostnamePrefixes)
			}
		}
	}
}

// --- endpoints -------------------------------------------------------------

func (r *Resolver) addHTTP(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		ua := rec.FirstStr("http.http_user_agent", "http.user_agent")
		applySubstringRules(d, "http.user_agent", ua, userAgents)
		applySubstringRules(d, "http.user_agent", ua, userAgentClass)
		r.checkEndOfLifeOS(d, ua)
	}
	if isPrivate(destIP) {
		d := r.device(destIP)
		if srv := rec.FirstStr("http.http_server", "http.server"); srv != "" {
			applySubstringRules(d, "http.server", srv, dhcpVendorClassSecondary)
			applySubstringRules(d, "http.server", srv, serverBanners)
			d.note("http.server", srv, "class=server", 0.3)
		}
		if host := rec.Str("http.hostname"); host != "" && !strings.Contains(host, ":") {
			d.addHostname(host)
		}
	}
}

func (r *Resolver) addTLS(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		// Client fingerprints identify the software stack initiating the
		// connection, and survive encryption.
		if h := rec.Str("tls.ja3.hash"); h != "" {
			d.JA3[h] = true
		}
		if h := rec.FirstStr("tls.ja4", "tls.ja4.hash"); h != "" {
			d.JA4[h] = true
		}
	}
	if !isPrivate(destIP) {
		return
	}
	d := r.device(destIP)
	subject := rec.Str("tls.subject")
	if subject != "" {
		if cn := commonName(subject); cn != "" {
			d.addHostname(cn)
		}
		d.note("tls.subject", subject, "class=server", 0.4)
		d.Certs = append(d.Certs, Cert{
			Subject:  subject,
			Issuer:   rec.Str("tls.issuerdn"),
			NotAfter: rec.FirstStr("tls.notafter", "tls.not_after"),
			Version:  rec.Str("tls.version"),
		})
		r.checkCertificate(d, subject, rec.Str("tls.issuerdn"),
			rec.FirstStr("tls.notafter", "tls.not_after"))
	}
	if sni := rec.Str("tls.sni"); sni != "" {
		d.addHostname(sni)
	}
	r.checkTLSVersion(d, rec.Str("tls.version"))
}

// addQUIC matters increasingly: as traffic moves to HTTP/3, SNI and client
// fingerprints migrate out of TLS records and into QUIC ones.
func (r *Resolver) addQUIC(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		d.Protocols["quic"] = true
		if h := rec.FirstStr("quic.ja4", "quic.ja3.hash"); h != "" {
			d.JA4[h] = true
		}
		if ua := rec.Str("quic.ua"); ua != "" {
			applySubstringRules(d, "quic.ua", ua, userAgents)
		}
	}
	if isPrivate(destIP) {
		d := r.device(destIP)
		if sni := rec.FirstStr("quic.sni", "quic.server_name"); sni != "" {
			d.addHostname(sni)
			d.note("quic.sni", sni, "class=server", 0.3)
		}
	}
}

func (r *Resolver) addSSH(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		banner := rec.FirstStr("ssh.server.software_version", "ssh.server.software")
		applySubstringRules(d, "ssh.server.banner", banner, sshBanners)
		if banner != "" {
			d.note("ssh.server.banner", banner, "class=server", 0.3)
		}
		if pv := rec.Str("ssh.server.proto_version"); pv == "1.0" || pv == "1.99" {
			r.addFinding(Finding{
				Severity: SevHigh, Kind: "ssh-v1", Device: destIP,
				Title:   "SSH protocol version 1 is enabled",
				Detail:  "SSHv1 has been broken for over twenty years. Anyone who can watch this connection can decrypt it.",
				Fix:     "Force protocol 2 in /etc/ssh/sshd_config and restart SSH. Nothing modern uses version 1, so this is safe to change.",
				Command: "sudo sed -i 's/^Protocol.*/Protocol 2/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
			})
		}
	}
	if isPrivate(srcIP) {
		banner := rec.FirstStr("ssh.client.software_version", "ssh.client.software")
		applySubstringRules(r.device(srcIP), "ssh.client.banner", banner, sshBanners)
	}
}

// addRDP is unusually informative: the client announces its own hostname during
// the connection handshake, in clear text.
func (r *Resolver) addRDP(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		d.note("rdp", "RDP client", "os=Windows", 0.6)
		if cn := rec.FirstStr("rdp.client.client_name", "rdp.client.hostname"); cn != "" {
			d.addHostname(cn)
		}
		if b := rec.Str("rdp.client.build"); b != "" {
			d.note("rdp.client.build", b, "class=workstation", 0.4)
		}
	}
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.note("rdp", "RDP service", "os=Windows", 0.7)
		d.note("rdp", "RDP service", "class=server", 0.4)
		if cn := rec.Str("rdp.tls.subject"); cn != "" {
			if n := commonName(cn); n != "" {
				d.addHostname(n)
			}
		}
	}
}

// addSNMP gives the single most precise identification available: sysDescr
// usually contains the exact vendor, model and firmware.
func (r *Resolver) addSNMP(rec *eve.Record, destIP string) {
	if !isPrivate(destIP) {
		return
	}
	d := r.device(destIP)
	d.note("snmp", "SNMP agent", "class=network", 0.6)

	if desc := rec.FirstStr("snmp.sysdescr", "snmp.sys_descr"); desc != "" {
		d.Model = desc
		applySubstringRules(d, "snmp.sysDescr", desc, dhcpVendorClass)
		applySubstringRules(d, "snmp.sysDescr", desc, serverBanners)
		d.noteSpec("snmp.sysDescr", desc, "vendor="+firstWord(desc), 0.8, 2)
	}
	// A default community string is an open door to device configuration.
	for _, c := range rec.Strings("snmp.community") {
		if lc := strings.ToLower(c); lc == "public" || lc == "private" {
			r.addFinding(Finding{
				Severity: SevHigh, Kind: "default-snmp-community", Device: destIP,
				Title:  "SNMP is using the default password \"" + lc + "\"",
				Detail: "\"public\" and \"private\" are the factory defaults every attacker tries first. Anyone on your network can read this device's full configuration, and with \"private\" can change it.",
				Fix:    "Open this device's admin page and either set a strong SNMP community string, or switch SNMP off entirely if nothing is monitoring it — which is usually the case.",
			})
		}
	}
	if v := rec.Str("snmp.version"); v == "1" || v == "2" || v == "2c" {
		r.addFinding(Finding{
			Severity: SevLow, Kind: "snmp-v1v2", Device: destIP,
			Title:  "SNMP v" + v + " in use",
			Detail: "SNMP v1 and v2c send their password across the network in plain text, so anyone watching can read it.",
			Fix:    "Switch this device to SNMPv3, which encrypts credentials. If the device is too old to support it, restrict SNMP to your management VLAN.",
		})
	}
}

// addRFB flags VNC, which is frequently exposed without authentication.
func (r *Resolver) addRFB(rec *eve.Record, destIP string) {
	if !isPrivate(destIP) {
		return
	}
	d := r.device(destIP)
	d.Protocols["vnc"] = true
	d.note("rfb", "VNC server", "class=server", 0.5)

	sec := strings.ToLower(rec.FirstStr("rfb.authentication.security_type_name", "rfb.security_type_name"))
	if strings.Contains(sec, "none") {
		r.addFinding(Finding{
			Severity: SevCritical, Kind: "vnc-no-auth", Device: destIP,
			Title:  "Remote desktop (VNC) needs no password",
			Detail: "Anyone who can reach this machine has full control of its screen, keyboard and mouse. No password is asked for.",
			Fix:    "Fix this today. Set a VNC password, or stop the VNC service if nobody is using it. If it is needed remotely, put it behind a VPN rather than exposing it on the network.",
		})
	}
}

// --- windows and directory --------------------------------------------------

// addSMB extracts Windows hostnames, usernames and exposed shares.
func (r *Resolver) addSMB(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		d.note("smb", "SMB client", "os=Windows", 0.4)
		if h := rec.Str("smb.ntlmssp.host"); h != "" {
			d.addHostname(h)
		}
		if u := rec.Str("smb.ntlmssp.user"); u != "" {
			d.Users[strings.ToLower(u)] = true
		}
	}
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.note("smb", "SMB service", "class=server", 0.4)
		if share := rec.Str("smb.share"); share != "" {
			d.Shares[share] = true
		}
		// SMB1 is the protocol behind WannaCry and is long deprecated.
		if dl := rec.Str("smb.dialect"); strings.HasPrefix(dl, "1.") || dl == "NT LM 0.12" {
			r.addFinding(Finding{
				Severity: SevHigh, Kind: "smbv1", Device: destIP,
				Title:   "SMBv1 file sharing is enabled",
				Detail:  "SMBv1 is how WannaCry and NotPetya spread through networks. Microsoft has been removing it since 2017.",
				Fix:     "Turn it off on this machine. Almost nothing still needs it — the exception is some very old scanners and NAS boxes, so check those first if file sharing stops working.",
				Command: "Windows:  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\nSamba:    add 'min protocol = SMB2' to smb.conf, then: sudo systemctl restart smbd",
			})
		}
	}
}

// addKerberos yields usernames and the AD realm — often the clearest picture of
// who is actually using a machine.
func (r *Resolver) addKerberos(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		if cn := rec.Str("krb5.cname"); cn != "" && !strings.HasSuffix(cn, "$") {
			d.Users[strings.ToLower(cn)] = true
			d.note("krb5.cname", cn, "class=workstation", 0.4)
		}
		d.note("krb5", "Kerberos client", "os=Windows", 0.3)
	}
	if isPrivate(destIP) {
		// Serving Kerberos is a strong signal for a domain controller.
		r.device(destIP).note("krb5", "Kerberos service", "class=server", 0.8)
	}
	// Weak Kerberos encryption is a common privilege-escalation route.
	if enc := strings.ToLower(rec.Str("krb5.encryption")); strings.Contains(enc, "rc4") ||
		strings.Contains(enc, "des") {
		r.addFinding(Finding{
			Severity: SevMedium, Kind: "weak-kerberos", Device: destIP,
			Title:  "Windows logins are using weak encryption (" + enc + ")",
			Detail: "RC4 and DES Kerberos tickets can be captured and cracked offline to recover account passwords. This is the basis of the well-known Kerberoasting attack.",
			Fix:    "In Group Policy, set 'Network security: Configure encryption types allowed for Kerberos' to AES128 and AES256 only. Test on a few machines first — very old systems may need updating.",
		})
	}
}

func (r *Resolver) addLDAP(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.Protocols["ldap"] = true
		d.note("ldap", "LDAP service", "class=server", 0.7)
	}
	if isPrivate(srcIP) {
		if dn := rec.FirstStr("ldap.request.bind_request.name", "ldap.bind.name"); dn != "" {
			r.device(srcIP).Users[strings.ToLower(dn)] = true
		}
	}
}

func (r *Resolver) addDCERPC(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.note("dcerpc", "DCERPC service", "os=Windows", 0.6)
		d.note("dcerpc", "DCERPC service", "class=server", 0.5)
	}
	if isPrivate(srcIP) {
		r.device(srcIP).note("dcerpc", "DCERPC client", "os=Windows", 0.4)
	}
}

func (r *Resolver) addNFS(rec *eve.Record, destIP string) {
	if !isPrivate(destIP) {
		return
	}
	d := r.device(destIP)
	d.note("nfs", "NFS export", "class=nas", 0.7)
	if share := rec.FirstStr("nfs.filename", "nfs.export"); share != "" {
		d.Shares[share] = true
	}
}

// --- servers and services ---------------------------------------------------

func (r *Resolver) addSMTP(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.Protocols["smtp"] = true
		d.note("smtp", "SMTP service", "class=server", 0.7)
		if h := rec.Str("smtp.helo"); h != "" {
			d.addHostname(h)
		}
	}
	if isPrivate(srcIP) {
		r.device(srcIP).Protocols["smtp"] = true
	}
}

func (r *Resolver) addSIP(rec *eve.Record, srcIP, destIP string) {
	for _, ip := range []string{srcIP, destIP} {
		if !isPrivate(ip) {
			continue
		}
		d := r.device(ip)
		d.Protocols["sip"] = true
		d.note("sip", "SIP telephony", "class=phone", 0.6)
		if ua := rec.FirstStr("sip.user_agent", "sip.request_line"); ua != "" {
			applySubstringRules(d, "sip.user_agent", ua, dhcpVendorClass)
		}
	}
}

func (r *Resolver) addMQTT(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.Protocols["mqtt"] = true
		d.note("mqtt", "MQTT broker", "class=iot", 0.6)
	}
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		d.Protocols["mqtt"] = true
		d.note("mqtt", "MQTT client", "class=iot", 0.7)
		if cid := rec.FirstStr("mqtt.connect.client_id", "mqtt.client_id"); cid != "" {
			d.addHostname(cid)
		}
	}
}

// --- file transfer ----------------------------------------------------------

// addFTP flags cleartext credentials, which is one of the highest-value findings
// a passive sensor can produce.
func (r *Resolver) addFTP(rec *eve.Record, srcIP, destIP string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.Protocols["ftp"] = true
		d.note("ftp", "FTP service", "class=server", 0.6)
		if b := rec.FirstStr("ftp.completion_code", "ftp.reply"); b != "" {
			applySubstringRules(d, "ftp.banner", b, serverBanners)
		}
	}
	cmd := strings.ToUpper(rec.Str("ftp.command"))
	if cmd == "USER" || cmd == "PASS" {
		r.addFinding(Finding{
			Severity: SevHigh, Kind: "cleartext-credentials", Device: destIP,
			Title:  "FTP password sent in plain text",
			Detail: "This username and password crossed the network readable by anyone able to see the traffic — including us, which is how we know.",
			Fix:    "Treat this password as compromised and change it. Then move the transfer to SFTP (port 22) or FTPS. Most FTP clients support SFTP with no other changes.",
		})
	}
	if isPrivate(srcIP) {
		r.device(srcIP).Protocols["ftp"] = true
	}
}

func (r *Resolver) addTFTP(rec *eve.Record, destIP string) {
	if !isPrivate(destIP) {
		return
	}
	d := r.device(destIP)
	d.Protocols["tftp"] = true
	// TFTP has no authentication at all and is common on embedded devices.
	d.note("tftp", "TFTP service", "class=network", 0.5)
	r.addFinding(Finding{
		Severity: SevMedium, Kind: "tftp-in-use", Device: destIP,
		Title:  "TFTP file transfer in use",
		Detail: "TFTP has no password and no encryption at all. It is normally used to move device firmware and configuration files — exactly the things you would not want copied or altered.",
		Fix:    "Restrict TFTP to your management VLAN, and switch the service off when you are not actively flashing firmware. Leaving it running permanently is the common mistake.",
	})
}

func (r *Resolver) addFileInfo(rec *eve.Record, srcIP, destIP string) {
	if d := r.localDevice(srcIP, destIP); d != nil {
		d.Files++
	}
	// Executables crossing the network are worth surfacing on their own.
	name := strings.ToLower(rec.FirstStr("fileinfo.filename", "files.filename"))
	for _, ext := range []string{".exe", ".dll", ".ps1", ".scr", ".bat", ".jar", ".vbs"} {
		if strings.HasSuffix(name, ext) {
			r.addFinding(Finding{
				Severity: SevLow, Kind: "executable-transfer", Device: destIP,
				Title:  "A program was downloaded onto this machine",
				Detail: "Observed: " + name + ". Usually harmless — but this is how most malware arrives, so it is worth a glance.",
				Fix:    "Ask whoever uses this machine whether they expected it. If you have the file hash, paste it into virustotal.com for a second opinion before doing anything else.",
			})
			break
		}
	}
}

// --- industrial / OT ---------------------------------------------------------

// addIndustrial marks control-system devices. These are the ones that must never
// be actively scanned, which is precisely why passive discovery matters here.
func (r *Resolver) addIndustrial(rec *eve.Record, srcIP, destIP, proto string) {
	if isPrivate(destIP) {
		d := r.device(destIP)
		d.Protocols[proto] = true
		d.noteSpec(proto, proto+" endpoint", "class=plc", 0.95, 2)
	}
	if isPrivate(srcIP) {
		d := r.device(srcIP)
		d.Protocols[proto] = true
		d.note(proto, proto+" client", "class=server", 0.3)
	}
	// Industrial protocols carry no authentication of their own. If one is
	// reachable from outside the OT segment, that is worth saying out loud.
	if isPrivate(destIP) && !isPrivate(srcIP) {
		r.addFinding(Finding{
			Severity: SevCritical, Kind: "ot-exposed", Device: destIP,
			Title:  "Industrial controller is reachable from outside your network",
			Detail: strings.ToUpper(proto) + " traffic reached this device from " + srcIP + ". Industrial protocols have no password of any kind — whoever can reach this device can send it commands.",
			Fix:    "Block this at your firewall today. Machine controllers should only be reachable from their own VLAN, and never from the internet. If remote access is genuinely needed, put it behind a VPN.",
		})
	}
}

// --- security and policy ------------------------------------------------------

func (r *Resolver) addAlert(rec *eve.Record, srcIP, destIP string) {
	if d := r.localDevice(srcIP, destIP); d != nil {
		d.Alerts++
	}
	sev := rec.Int("alert.severity")
	sig := rec.Str("alert.signature")
	// Suricata severity 1 is its highest. Surface those; leave the rest to the
	// alert view rather than cluttering findings.
	if sev == 1 && sig != "" {
		dev := destIP
		if isPrivate(srcIP) {
			dev = srcIP
		}
		r.addFinding(Finding{
			Severity: SevHigh, Kind: "high-severity-alert", Device: dev,
			Title:  "Threat detected: " + sig,
			Detail: "Suricata's rules flagged this as a serious match. " + srcIP + " → " + destIP,
			Fix:    "Look at what else this device has been doing — the timeline and connection list on this page are the fastest way. If it is a device that should not be talking to the internet at all, such as a camera or a controller, block it and investigate.",
		})
	}
}

func (r *Resolver) addBitTorrent(srcIP string) {
	if !isPrivate(srcIP) {
		return
	}
	r.device(srcIP).Protocols["bittorrent"] = true
	r.addFinding(Finding{
		Severity: SevLow, Kind: "p2p", Device: srcIP,
		Title:  "Peer-to-peer file sharing detected",
		Detail: "BitTorrent traffic from this device. Usually a staff-policy matter rather than a security one, though it can carry copyright and malware risk.",
		Fix:    "Decide whether this is allowed. If not, block BitTorrent at the firewall and have a word with whoever uses this machine.",
	})
}

// --- topology -----------------------------------------------------------------

// addFlow establishes which side of a conversation is serving, and records
// external destinations for later "this has never happened before" checks.
func (r *Resolver) addFlow(rec *eve.Record, srcIP, destIP string) {
	destPort := rec.Int("dest_port")
	proto := strings.ToLower(rec.Str("proto"))
	appProto := rec.Str("app_proto")

	if isPrivate(destIP) && destPort > 0 {
		d := r.device(destIP)
		d.addService(destPort, proto, appProto)
		if rule, ok := portRules[destPort]; ok {
			d.note("service.port", itoa(destPort)+" ("+rule.Note+")", rule.Conclusion, rule.Weight)
		}
	}
	if isPrivate(srcIP) && !isPrivate(destIP) && destIP != "" {
		r.device(srcIP).ExternalDsts[destIP] = true
	}

	// Industrial traffic often arrives as a flow record carrying app_proto
	// rather than as a dedicated modbus/dnp3/enip event, because those event
	// types are only emitted when explicitly configured. Check here too —
	// a control system reachable from outside the network is the single most
	// serious thing this tool can find, and it must not depend on how the
	// sensor happens to be configured.
	switch appProto {
	case "modbus", "dnp3", "enip":
		r.addIndustrial(rec, srcIP, destIP, appProto)
	}
}

// --- the sensor itself ---------------------------------------------------------

// addStats reads Suricata's own counters. A sensor dropping packets produces a
// quietly incomplete picture, which is more dangerous than one that is plainly
// offline — so this is surfaced rather than kept internal.
func (r *Resolver) addStats(rec *eve.Record) {
	h := &r.SensorHealth
	h.Reported = true
	if u := rec.Int("stats.uptime"); u > 0 {
		h.Uptime = u
	}
	if c := rec.Int("stats.capture.kernel_packets"); c > 0 {
		h.PacketsCaptured = c
	}
	if dr := rec.Int("stats.capture.kernel_drops"); dr > 0 {
		h.PacketsDropped = dr
	}
	if h.PacketsCaptured > 0 {
		pct := float64(h.PacketsDropped) / float64(h.PacketsCaptured) * 100
		if pct > 1 {
			r.addFinding(Finding{
				Severity: SevMedium, Kind: "sensor-packet-loss", Device: "sensor",
				Title:  "The sensor is missing traffic",
				Detail: "Suricata dropped a meaningful share of what it captured, so this inventory is incomplete. A sensor that is quietly half-blind is more dangerous than one that is plainly offline.",
				Fix:    "Give the sensor more capacity: raise ring-size in suricata.yaml, give the machine more CPU cores, or mirror less traffic to it. On a busy 1 Gbps link a 2-core box is usually the limit.",
			})
		}
	}
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t,;"); i > 0 {
		return s[:i]
	}
	return s
}
