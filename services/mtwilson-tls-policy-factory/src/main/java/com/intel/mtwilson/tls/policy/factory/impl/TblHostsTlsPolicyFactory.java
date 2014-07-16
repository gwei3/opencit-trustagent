/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.mtwilson.tls.policy.factory.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.crypto.SimpleKeystore;
import com.intel.dcsg.cpg.io.Resource;
import com.intel.dcsg.cpg.net.InternetAddress;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.My;
import com.intel.mtwilson.as.data.TblHosts;
import com.intel.mtwilson.datatypes.ConnectionString;
import com.intel.mtwilson.datatypes.TxtHostRecord;
import com.intel.mtwilson.tls.policy.TlsPolicyChoice;
import com.intel.mtwilson.tls.policy.TlsPolicyDescriptor;
import com.intel.mtwilson.tls.policy.TlsProtection;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyFactory;
import com.intel.mtwilson.tls.policy.factory.TlsPolicyProvider;
import com.intel.mtwilson.tls.policy.provider.StoredTlsPolicy;
import com.intel.mtwilson.tls.policy.provider.StoredVendorTlsPolicy;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;

/**
 *
 * @author jbuhacoff
 */
public class TblHostsTlsPolicyFactory extends TlsPolicyFactory {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TblHostsTlsPolicyFactory.class);
    private TlsPolicyProvider objectTlsPolicyProvider;
    private StoredTlsPolicy.HostDescriptor hostDescriptor;
    private StoredVendorTlsPolicy.VendorDescriptor vendorDescriptor;

    /**
     * Example input:
     * <pre>
     * 2014-07-06 05:17:03,408 DEBUG [http-bio-8443-exec-130] c.i.m.t.p.f.i.TblHostsTlsPolicyFactory [TblHostsTlsPolicyFactory.java:56] TblHostsTlsPolicyFactory constructor: {"tblSamlAssertionCollection":null,"location":null,"id":null,"name":"10.1.71.173","port":0,"description":null,"aikSha1":null,"aikPublicKey":null,"aikPublicKeySha1":null,"tlsPolicyId":null,"tlsPolicyName":null,"tlsKeystore":null,"email":null,"errorCode":null,"errorDescription":null,"vmmMleId":null,"biosMleId":null,"uuid_hex":null,"bios_mle_uuid_hex":null,"vmm_mle_uuid_hex":null,"tlsPolicyChoice":{"tlsPolicyId":null,"tlsPolicyDescriptor":null},"tlsPolicyDescriptor":null,"ipaddress":"10.1.71.173","addOnConnectionInfo":"vmware:https://10.1.71.162:443/sdk;administrator;intel123!","aikcertificate":null,"hardwareUuid":null}
2014-07-06 05:17:03,408 DEBUG [http-bio-8443-exec-130] c.i.m.t.p.f.i.TblHostsTlsPolicyFactory$TblHostsObjectTlsPolicy [TblHostsTlsPolicyFactory.java:144] TblHostsObjectTlsPolicy: policy not found in TblHosts record

     * </pre>
     * @param tblHosts 
     */
    public TblHostsTlsPolicyFactory(TblHosts tblHosts) {
        super();
//        try {
//            ObjectMapper mapper = new ObjectMapper();
//            log.debug("TblHostsTlsPolicyFactory constructor: {}", mapper.writeValueAsString(tblHosts)); //This statement may contain clear text passwords
//        } catch (Exception e) {
//            log.warn("Cannot write debug log", e);
//        }
//        this.txtHostRecord = txtHostRecord;
        this.objectTlsPolicyProvider = new TblHostsObjectTlsPolicy(tblHosts);
        this.hostDescriptor = new TblHostsHostDescriptor(tblHosts);
        this.vendorDescriptor = new TblHostsVendorDescriptor(tblHosts);
    }

    /*
     @Override
     protected boolean accept(Object tlsPolicySubject) {
     return tlsPolicySubject instanceof TblHosts;
     }
     */
    @Override
    protected TlsPolicyProvider getObjectTlsPolicyProvider() {
        return objectTlsPolicyProvider;
    }

    @Override
    protected StoredTlsPolicy.HostDescriptor getHostDescriptor() {
        return hostDescriptor;
    }

    @Override
    protected StoredVendorTlsPolicy.VendorDescriptor getVendorDescriptor() {
        return vendorDescriptor;
    }

    public static class TblHostsObjectTlsPolicy implements TlsPolicyProvider {

        private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TblHostsObjectTlsPolicy.class);
        private TlsPolicyChoice tlsPolicyChoice;
        // used only for initTlsTrustedCertificateAuthorities
        private long tlsPemLastModified = 0;
        private long tlsCrtLastModified = 0;
        private ArrayList<X509Certificate> tlsAuthorities = new ArrayList<>();

        public TblHostsObjectTlsPolicy(TblHosts tblHosts) {
            this.tlsPolicyChoice = determineTlsPolicyChoice(tblHosts);
        }

        private TlsPolicyChoice determineTlsPolicyChoice(TblHosts host) {
            // first look at the new tlsPolicyId field
            if (host.getTlsPolicyId() != null && !host.getTlsPolicyId().isEmpty()) {
                log.debug("TblHostsObjectTlsPolicy: policy id {}", host.getTlsPolicyId());
                // the caller can load the specified policy from the database
                TlsPolicyChoice tlsPolicyIdChoice = new TlsPolicyChoice();
                tlsPolicyIdChoice.setTlsPolicyId(host.getTlsPolicyId());
                return tlsPolicyIdChoice;
            }
            // second, look for a (temporary) tls policy descriptor
            if (host.getTlsPolicyDescriptor() != null) {
                log.debug("TblHostsObjectTlsPolicy: policy descriptor {}", host.getTlsPolicyDescriptor().getPolicyType());
                TlsPolicyChoice tlsPolicyIdChoice = new TlsPolicyChoice();
                tlsPolicyIdChoice.setTlsPolicyDescriptor(host.getTlsPolicyDescriptor());
                return tlsPolicyIdChoice;
            } // third, for backward compatibility, recognize the Mt Wilson 1.x policy types
            else if (host.getTlsPolicyName() != null && !host.getTlsPolicyName().isEmpty()) {
                log.debug("TblHostsObjectTlsPolicy: policy name {}", host.getTlsPolicyName());
                if (host.getTlsPolicyName().equals("INSECURE")) {
                    TlsPolicyChoice tlsPolicyNameChoice = new TlsPolicyChoice();
                    tlsPolicyNameChoice.setTlsPolicyDescriptor(new TlsPolicyDescriptor());
                    tlsPolicyNameChoice.getTlsPolicyDescriptor().setPolicyType(host.getTlsPolicyName());
                    return tlsPolicyNameChoice;
                } else if (host.getTlsPolicyName().equals("TRUST_FIRST_CERTIFICATE")) {
                    TlsPolicyChoice tlsPolicyNameChoice = new TlsPolicyChoice();
                    tlsPolicyNameChoice.setTlsPolicyDescriptor(new TlsPolicyDescriptor());
                    tlsPolicyNameChoice.getTlsPolicyDescriptor().setPolicyType(host.getTlsPolicyName());
                    // TODO:  need to provide something here for savnig the cert back???? no... must be provided via some other interface... because the choice/descriptor objects are data contains only, not pure oo...
                    return tlsPolicyNameChoice;
                } else if (host.getTlsPolicyName().equals("TRUST_KNOWN_CERTIFICATE")) {
                    // BOOKMARK JONATHAN TLS POLICY
                    TlsPolicyChoice tlsPolicyNameChoice = new TlsPolicyChoice();
                    tlsPolicyNameChoice.setTlsPolicyDescriptor(getTlsPolicyDescriptorFromResource(host.getTlsPolicyName(), host.getTlsKeystoreResource()));
                    return tlsPolicyNameChoice;
                } else if (host.getTlsPolicyName().equals("TRUST_CA_VERIFY_HOSTNAME")) {
                    // BOOKMARK JONATHAN TLS POLICY
                    TlsPolicyChoice tlsPolicyNameChoice = new TlsPolicyChoice();
                    tlsPolicyNameChoice.setTlsPolicyDescriptor(getTlsPolicyDescriptorFromResource(host.getTlsPolicyName(), host.getTlsKeystoreResource()));
                    return tlsPolicyNameChoice;
                } else {
                    log.debug("TblHostsObjectTlsPolicy: unsupported policy name {}", host.getTlsPolicyName());
                    return null;
                }
            } else {
                log.debug("TblHostsObjectTlsPolicy: policy not found in TblHosts record");
                return null;
            }
        }

        @Override
        public TlsPolicyChoice getTlsPolicyChoice() {
            return tlsPolicyChoice;
        }

        private TlsPolicyDescriptor getTlsPolicyDescriptorFromResource(String tlsPolicyName, Resource resource)  {
            try {
                String password = My.configuration().getTlsKeystorePassword();
                SimpleKeystore tlsKeystore = new SimpleKeystore(resource, password); // XXX TODO only because txthost doesn't have the field yet... we should get the keystore from the txthost object
                TlsPolicyDescriptor tlsPolicyDescriptor = getTlsPolicyDescriptorFromKeystore(tlsPolicyName, tlsKeystore); // XXX TODO not sure that this belongs in the http-authorization package, because policy names are an application-level thing (allowed configurations), and creating the right repository is an application-level thing too (mutable vs immutable, and underlying implementation - keystore, array, cms of pem-list.
                return tlsPolicyDescriptor;
            }
            catch(KeyManagementException e) {
                log.warn("Cannot load tls policy descriptor", e);
                return null;
            }
        }

        private List<X509Certificate> getMtWilson1xTrustedTlsCertificates() {
            try {
                initTlsTrustedCertificateAuthorities();
                return tlsAuthorities;
            } catch (IOException e) {
                log.warn("Cannot load trusted TLS certificates from Mt Wilson 1.x configuration", e);
                return Collections.EMPTY_LIST;
            }
        }

        private List<X509Certificate> getTrustedTlsCertificatesFromSimpleKeystore(SimpleKeystore tlsKeystore) {
            ArrayList<X509Certificate> list = new ArrayList<>();
            if (tlsKeystore != null) {
                try {
                    X509Certificate[] cacerts = tlsKeystore.getTrustedCertificates(SimpleKeystore.CA);
                    list.addAll(Arrays.asList(cacerts));
                    X509Certificate[] sslcerts = tlsKeystore.getTrustedCertificates(SimpleKeystore.SSL);
                    list.addAll(Arrays.asList(sslcerts));
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException | CertificateEncodingException e) {
                    log.warn("Cannot load trusted TLS certificates from Mt Wilson 1.x keystore", e);

                }
            }
            return list;
        }

        @Deprecated
        private TlsPolicyDescriptor getTlsPolicyDescriptorFromKeystore(String tlsPolicyName, SimpleKeystore tlsKeystore) {
            if (tlsPolicyName == null) {
                tlsPolicyName = My.configuration().getDefaultTlsPolicyId();
            }
            String ucName = tlsPolicyName.toUpperCase();
            if (ucName.equals("TRUST_CA_VERIFY_HOSTNAME")) {
                TlsProtection tlsProtection = new TlsProtection();
                tlsProtection.integrity = true;
                tlsProtection.encryption = true;
                tlsProtection.authentication = true;
                tlsProtection.forwardSecrecy = true;
                TlsPolicyDescriptor tlsPolicyDescriptor = new TlsPolicyDescriptor();
                tlsPolicyDescriptor.setPolicyType("certificate");
                tlsPolicyDescriptor.setProtection(tlsProtection);
                ArrayList<String> encodedCertificates = new ArrayList<>();
                tlsPolicyDescriptor.setData(encodedCertificates);

                // combine mtwilson 1.x ca certs configuration and per-host cacerts and certs configuration into one certificate policy
                ArrayList<X509Certificate> certificates = new ArrayList<>();
                certificates.addAll(getMtWilson1xTrustedTlsCertificates());
                certificates.addAll(getTrustedTlsCertificatesFromSimpleKeystore(tlsKeystore));

                // encode each certificate into the descriptor
                for (X509Certificate cert : certificates) {
                    log.debug("Adding trusted TLS certs and cacerts: {}", cert.getSubjectX500Principal().getName());
                    try {
                        encodedCertificates.add(Base64.encodeBase64String(cert.getEncoded()));
                    } catch (CertificateEncodingException e) {
                        throw new IllegalArgumentException("Invalid certificate", e);
                    }
                }
                return tlsPolicyDescriptor;
            }
            if (ucName.equals("TRUST_FIRST_CERTIFICATE")) {
                TlsPolicyDescriptor tlsPolicyDescriptor = new TlsPolicyDescriptor();
                tlsPolicyDescriptor.setPolicyType("TRUST_FIRST_CERTIFICATE");
                ArrayList<String> certificates = new ArrayList<>();
                tlsPolicyDescriptor.setData(certificates);
                return tlsPolicyDescriptor;
            }
            if (ucName.equals("TRUST_KNOWN_CERTIFICATE")) {
                TlsProtection tlsProtection = new TlsProtection();
                tlsProtection.integrity = true;
                tlsProtection.encryption = true;
                tlsProtection.authentication = true;
                tlsProtection.forwardSecrecy = true;
                TlsPolicyDescriptor tlsPolicyDescriptor = new TlsPolicyDescriptor();
                tlsPolicyDescriptor.setPolicyType("public-key");
                tlsPolicyDescriptor.setProtection(tlsProtection);
                ArrayList<String> encodedPublicKeys = new ArrayList<>();
                tlsPolicyDescriptor.setData(encodedPublicKeys);

                // combine mtwilson 1.x ca certs configuration and per-host cacerts and certs configuration into one certificate policy
                ArrayList<X509Certificate> certificates = new ArrayList<>();
                certificates.addAll(getMtWilson1xTrustedTlsCertificates());
                certificates.addAll(getTrustedTlsCertificatesFromSimpleKeystore(tlsKeystore));

                // encode each certificate into the descriptor
                for (X509Certificate cert : certificates) {
                    log.debug("Adding trusted TLS certificate public keys: {}", cert.getSubjectX500Principal().getName());
                    encodedPublicKeys.add(Base64.encodeBase64String(cert.getPublicKey().getEncoded()));
                }
                return tlsPolicyDescriptor;
            }
            if (ucName.equals("INSECURE")) {
                TlsPolicyDescriptor tlsPolicyDescriptor = new TlsPolicyDescriptor();
                tlsPolicyDescriptor.setPolicyType("INSECURE");
                return tlsPolicyDescriptor;
            }
            throw new IllegalArgumentException("Unknown TLS Policy: " + tlsPolicyName);

        }

        // for backward compatibility, can load the mtwilson 1.x trusted tls cacerts file
        @Deprecated
        private void initTlsTrustedCertificateAuthorities() throws IOException {
            // read the trusted CA's
            String tlsCaFilename = My.configuration().getConfiguration().getString("mtwilson.tls.certificate.file", "mtwilson-tls.pem");
            if (tlsCaFilename != null) {
                if (!tlsCaFilename.startsWith("/")) {
                    tlsCaFilename = String.format("/etc/intel/cloudsecurity/%s", tlsCaFilename);// XXX TODO assuming linux ,but could be windows ... need to use platform-dependent configuration folder location
                }
                if (tlsCaFilename.endsWith(".pem")) {
                    File tlsPemFile = new File(tlsCaFilename);
                    if (tlsPemFile.lastModified() > tlsPemLastModified) {
                        tlsPemLastModified = tlsPemFile.lastModified();
                        tlsAuthorities.clear();
                        try (FileInputStream in = new FileInputStream(tlsPemFile)) {
                            String content = IOUtils.toString(in);
                            List<X509Certificate> cacerts = X509Util.decodePemCertificates(content);
                            tlsAuthorities.addAll(cacerts);
                        } catch (CertificateException e) {
                            log.error("Cannot read trusted TLS CA certificates", e);
                        }
                    }
                }
                if (tlsCaFilename.endsWith(".crt")) {
                    File tlsCrtFile = new File(tlsCaFilename);
                    if (tlsCrtFile.lastModified() > tlsCrtLastModified) {
                        tlsCrtLastModified = tlsCrtFile.lastModified();
                        tlsAuthorities.clear();
                        try (FileInputStream in = new FileInputStream(tlsCrtFile)) {
                            byte[] content = IOUtils.toByteArray(in);
                            X509Certificate cert = X509Util.decodeDerCertificate(content);
                            tlsAuthorities.add(cert);
                        } catch (CertificateException e) {
                            log.error("Cannot read trusted TLS CA certificates", e);
                        }
                    }
                }
            }
        }
    }

    public static class TblHostsHostDescriptor implements StoredTlsPolicy.HostDescriptor {

        private String hostId;
        private InternetAddress hostname;

        public TblHostsHostDescriptor(TblHosts tblHosts) {
            this.hostId = tblHosts.getName();
            ConnectionString str = getConnectionString(tblHosts);
            if (str == null) {
                throw new IllegalArgumentException(String.format("Cannot determine connection string for host: ", tblHosts.getName()));
            }
            log.debug("TblHosts connection string with prefix: {}", str.getConnectionStringWithPrefix());
            log.debug("TblHosts connection string: {}", str.getConnectionString());
//            log.debug("TblHosts connection string: {}", str.getURL().toExternalForm());
            log.debug("TblHosts connection string addon conn str: {}", str.getAddOnConnectionString());
            this.hostname = new InternetAddress(str.getManagementServerName()); // not using tblHosts.getName() because in case of vcenter or xencenter the hostname is not the address we're connecting to; but the ConnectionString class always presents the connection target a this attribute
        }

        @Override
        public String getHostId() {
            return hostId;
        }

        @Override
        public InternetAddress getInternetAddress() {
            return hostname;
        }
    }

    public static class TblHostsVendorDescriptor implements StoredVendorTlsPolicy.VendorDescriptor {

        private String vendor;

        public TblHostsVendorDescriptor(TblHosts tblHosts) {
            ConnectionString str = getConnectionString(tblHosts);
            if (str != null) {
                this.vendor = str.getVendor().name();
            }
        }

        @Override
        public String getVendorProtocol() {
            return vendor;
        }
    }

    protected static ConnectionString getConnectionString(TblHosts tblHosts) {
        try {
            TxtHostRecord txtHostRecord = new TxtHostRecord();
            txtHostRecord.AddOn_Connection_String = tblHosts.getAddOnConnectionInfo();
            txtHostRecord.HostName = tblHosts.getName();
            txtHostRecord.Port = tblHosts.getPort();
            txtHostRecord.IPAddress = tblHosts.getIPAddress();
            ConnectionString str = ConnectionString.from(txtHostRecord);
            return str;
        } catch (MalformedURLException e) {
            log.error("Cannot determine connection string from host record", e);
            return null;
        }
    }
}