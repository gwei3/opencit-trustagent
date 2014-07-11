/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.mtwilson.My;
//import com.intel.mtwilson.agent.intel.IntelHostAgentFactory;
//import com.intel.mtwilson.agent.vmware.VmwareHostAgentFactory;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.dcsg.cpg.crypto.SimpleKeystore;
import com.intel.dcsg.cpg.extensions.Extensions;
import com.intel.mtwilson.model.InternetAddress;
import com.intel.mtwilson.model.PcrManifest;
import com.intel.dcsg.cpg.tls.policy.TlsPolicy;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyFactory;
//import com.intel.dcsg.cpg.tls.policy.TrustCaAndVerifyHostnameTlsPolicy;
//import com.intel.dcsg.cpg.tls.policy.TrustFirstCertificateTlsPolicy;
//import com.intel.dcsg.cpg.tls.policy.TrustKnownCertificateTlsPolicy;
import java.io.IOException;
import java.security.KeyManagementException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import com.intel.mtwilson.agent.citrix.CitrixHostAgentFactory;
//import com.intel.mtwilson.agent.citrix.CitrixHostAgent;
import com.intel.mtwilson.datatypes.ConnectionString;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import java.util.HashMap;
import java.util.List;

/**
 * Use this class to instantiate the appropriate agent or client for a given
 * host. It looks primarily at the "AddOn_Connection_String".
 * 
 * Use of the TblHosts object: getName(), getPort(), getTlsPolicyName(), 
 * getTlsPolicyResource().
 * 
 * @throws UnuspportedOperationException if the appropriate agent type cannot be determined from the given host
 * @author jbuhacoff
 */
public class HostAgentFactory {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private Map<String,VendorHostAgentFactory> vendorFactoryMap = new HashMap<>();
    
    public HostAgentFactory() {
//        vendorFactoryMap.put(Vendor.INTEL, new IntelHostAgentFactory());
//        vendorFactoryMap.put(Vendor.CITRIX, new CitrixHostAgentFactory());
//        vendorFactoryMap.put(Vendor.VMWARE, new VmwareHostAgentFactory());
        List<VendorHostAgentFactory> vendorHostAgentFactories = Extensions.findAll(VendorHostAgentFactory.class);
        for(VendorHostAgentFactory vendorHostAgentFactory : vendorHostAgentFactories) {
            vendorFactoryMap.put(vendorHostAgentFactory.getVendorProtocol(), vendorHostAgentFactory);
            
        }
    }
    
    /**
     * It is recommended to supply an EnumMap instance
     * @param map of vendor host agent factories
     */
    public void setVendorFactoryMap(Map<String,VendorHostAgentFactory> map) {
        vendorFactoryMap = map;
    }
        
    private TxtHostRecord convert(TblHosts input) {
        TxtHostRecord converted = new TxtHostRecord();
        converted.AIK_Certificate = input.getAIKCertificate();
        converted.AIK_PublicKey = input.getAikPublicKey();
        converted.AIK_SHA1 = input.getAikSha1();
        converted.AddOn_Connection_String = input.getAddOnConnectionInfo();
        converted.BIOS_Name = (input.getBiosMleId() == null ? null : input.getBiosMleId().getName());
        converted.BIOS_Version = (input.getBiosMleId() == null ? null : input.getBiosMleId().getVersion());
        converted.BIOS_Oem = (input.getBiosMleId() == null || input.getBiosMleId().getOemId() == null ? null : input.getBiosMleId().getOemId().getName());
        converted.Description = input.getDescription();
        converted.Email = input.getEmail();
        converted.Hardware_Uuid = input.getHardwareUuid();
        converted.HostName = input.getName();
        converted.IPAddress = input.getIPAddress();
        converted.Location = input.getLocation();
        converted.Port = input.getPort();
//        converted.Processor_Info
        converted.VMM_Name = (input.getVmmMleId() == null ? null : input.getVmmMleId().getName());
        converted.VMM_Version = (input.getVmmMleId() == null ? null : input.getVmmMleId().getVersion());
        converted.VMM_OSName = (input.getVmmMleId() == null || input.getVmmMleId().getOsId() == null ? null : input.getVmmMleId().getOsId().getName());
        converted.VMM_OSVersion = (input.getVmmMleId() == null || input.getVmmMleId().getOsId() == null ? null : input.getVmmMleId().getOsId().getVersion());
        converted.tlsPolicyChoice = input.getTlsPolicyChoice();
        return converted;
    }
    
    /**
     * BUG #497   given a host record, this method creates an appropriate HostAgent
     * object (for vmware, citrix, or intel hosts) and its TLS Policy. 
     * Currently only our vmware code implements HostAgent, need to implement it
     * also in our citrix and intel code. 
     * @param txtHost must have Name, AddOnConnectionInfo, SSLPolicy, and SSLCertificate fields set
     * @return 
     */
    public HostAgent getHostAgent(TblHosts host) {
        // debug only
        try {
        ObjectMapper mapper = new ObjectMapper();
//        log.debug("getHostAgent TblHosts: {}", mapper.writeValueAsString(host)); // infinite recursion because of the automatic database links, tblHosts -> tblSamlAssertionCollection -> first item -> tblHosts again
        log.debug("getHostAgent TblHosts tlsPolicyId: {}", host.getTlsPolicyId());
        log.debug("getHostAgent TblHosts tlsPolicyDescriptor: {}", mapper.writeValueAsString(host.getTlsPolicyDescriptor()));
        log.debug("getHostAgent TblHosts tlsPolicyName (deprecated): {}", host.getTlsPolicyName());
        log.debug("getHostAgent TblHosts tlsKeystore (deprecated): {} bytes", (host.getTlsKeystore()==null?"null":host.getTlsKeystore().length));
        } catch(Exception e) { log.error("getHostAgent cannot serialize TblHosts" ,e); }
        // debug only
        
        return getHostAgent(convert(host));
    }
    
    public HostAgent getHostAgent(TxtHostRecord host) {
        // debug only
        try {
        ObjectMapper mapper = new ObjectMapper();
        log.debug("getHostAgent TxtHostRecord: {}", mapper.writeValueAsString(host));
        } catch(Exception e) { log.error("getHostAgent cannot serialize TxtHostRecord" ,e); }
        // debug only
        
        String address = host.HostName;
        if( address == null || address.isEmpty() ) { address = host.IPAddress; }
        try {
            
            InternetAddress hostAddress = new InternetAddress(address); // switching from Hostname to InternetAddress (better support for both hostname and ip address)
            ConnectionString connectionString = ConnectionString.from(host);
            log.debug("Retrieving TLS policy...");
            TlsPolicy tlsPolicy = getTlsPolicy(host);
            log.debug("Creating Host Agent for host: {}" , address);
            HostAgent ha = getHostAgent(hostAddress, connectionString, tlsPolicy); // XXX TODO need to have a way for the agent using trust-first-certificate to save a new certificate to the TblHosts record... right now it is lost.
            log.debug("Host Agent created.");
            return ha;
        }
        catch(IOException | RuntimeException e) {
            throw new IllegalArgumentException("Cannot create Host Agent for "+address+": "+e.toString(), e);
        }
    }    
    
    public TlsPolicy getTlsPolicy(TxtHostRecord host)  {
//        if( host.getTlsPolicyName() == null ) {
//            host.setTlsPolicyName(My.configuration().getDefaultTlsPolicyName());
//        }
//        ByteArrayResource resource = new ByteArrayResource(host.getTlsKeystore() == null ? new byte[0] : host.getTlsKeystore()); // XXX TODO we need to get tie the keystore to the database, especially for TRUST_FIRST_CERTIFICATE, so if it's the first connection we can save the certificate back to the database after connecting
//        KeyStore tlsKeystore = txtHost.getTlsKeystore(); // XXX TODO TxtHost doesn't have this field yet
//        TlsPolicy tlsPolicy = tlsPolicyFactory.getTlsPolicyWithKeystore(host.getTlsPolicyName(), host.getTlsKeystoreResource());
        TlsPolicyFactory tlsPolicyFactory = TlsPolicyFactory.createFactory(host);//getTlsPolicyWithKeystore(tlsPolicyName, tlsKeystore);
        TlsPolicy tlsPolicy = tlsPolicyFactory.getTlsPolicy();
        return tlsPolicy;
    }

    /**
     * 
     * @param connectionString what is also known as the "AddOn_Connection_String", in the form vendor:url, for example vmware:https://vcenter.com/sdk;Administrator;password
     * @return 
     */
    private HostAgent getHostAgent(InternetAddress hostAddress, ConnectionString cs, TlsPolicy tlsPolicy) throws IOException {
        if( cs == null ) {
            throw new IllegalArgumentException("Connection info missing"); // XXX it is missing for intel trust agents configured in 1.0-RC2 or earlier -- should we attempt to guess intel:https://hostaddress:9999 for backwards compatibility?  also we don't have a vendor host agent factory for intel trust agent yet!!
        }
        String vendorProtocol = cs.getVendor().name().toLowerCase(); // INTEL, CITRIX, VMWARE becomes intel, citrix, vmware
        if( vendorFactoryMap.containsKey(vendorProtocol) ) {
            VendorHostAgentFactory factory = vendorFactoryMap.get(vendorProtocol);
            if( factory != null ) {
                return factory.getHostAgent(hostAddress, cs.getConnectionString(), tlsPolicy);
            }
        }
        log.error("HostAgentFactory: Unsupported host type: "+vendorProtocol);
        throw new UnsupportedOperationException("Unsupported host type: "+vendorProtocol);
    }
    
    
    public HostAgent getHostAgent(ConnectionString hostConnection, TlsPolicy tlsPolicy) throws IOException {
        if( hostConnection == null ) {
            throw new IllegalArgumentException("Connection info missing"); // XXX it is missing for intel trust agents configured in 1.0-RC2 or earlier -- should we attempt to guess intel:https://hostaddress:9999 for backwards compatibility?  also we don't have a vendor host agent factory for intel trust agent yet!!
        }
        String vendorProtocol = hostConnection.getVendor().name().toLowerCase();
        if( vendorFactoryMap.containsKey(vendorProtocol) ) { // intel, citrix, vmware
            VendorHostAgentFactory factory = vendorFactoryMap.get(vendorProtocol);
                if( factory != null ) {
                    return factory.getHostAgent(hostConnection.getConnectionString(), tlsPolicy);
                }
        }
        throw new UnsupportedOperationException("No agent factory registered for this host");
    }
    
}
