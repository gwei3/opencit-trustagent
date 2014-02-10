/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.as.rest.v2.repository;

import com.intel.mtwilson.as.rest.v2.model.CaCertificate;
import com.intel.mtwilson.as.rest.v2.model.CaCertificateCollection;
import com.intel.mtwilson.ms.common.MSException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import org.apache.commons.io.IOUtils;
import com.intel.mtwilson.as.rest.v2.model.CaCertificateFilterCriteria;
import com.intel.mtwilson.as.rest.v2.model.CaCertificateLocator;
//import com.intel.mtwilson.datatypes.ApiClientCreateRequest;
//import com.intel.mtwilson.datatypes.ApiClientStatus;
//import com.intel.mtwilson.datatypes.ApiClientUpdateRequest;
import com.intel.mtwilson.datatypes.ErrorCode;
import com.intel.mtwilson.jersey.resource.SimpleRepository;
import com.intel.mtwilson.ms.common.MSConfig;
//import com.intel.mtwilson.ms.controller.ApiClientX509JpaController;
//import com.intel.mtwilson.ms.data.ApiClientX509;
//import com.intel.mtwilson.ms.data.ApiRoleX509;
//import com.intel.mtwilson.ms.business.ApiClientBO;
//import com.intel.mtwilson.ms.common.MSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
public class CaCertificateRepository implements SimpleRepository<CaCertificate, CaCertificateCollection, CaCertificateFilterCriteria, CaCertificateLocator> {

    private Logger log = LoggerFactory.getLogger(getClass().getName());
        
    @Override
    public CaCertificateCollection search(CaCertificateFilterCriteria criteria) {
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public CaCertificate retrieve(CaCertificateLocator locator) {
        if (locator == null || locator.id == null) { return null;}
        CaCertificate caCert = new CaCertificate();
        
        if ("root".endsWith(locator.id)) {
            try {
                String certFile = MSConfig.getConfiguration().getString("mtwilson.rootca.certificate.file");
                if( certFile != null && !certFile.startsWith(File.separator) ) {
                    certFile = "/etc/intel/cloudsecurity/" + certFile;
                }
                if(certFile != null) {
                    File rootCaPemFile = new File(certFile); 
                    FileInputStream in = new FileInputStream(rootCaPemFile);
                    caCert.setCertificate(IOUtils.toByteArray(in));
                    IOUtils.closeQuietly(in);
                } else {
                    throw new FileNotFoundException("Could not obtain Root CA cert location from config");
                }
            } 
            catch (FileNotFoundException e) {
                log.error("Mt Wilson Root CA certificate file is not found. ", e);
                throw new MSException(ErrorCode.MS_ROOT_CA_CERT_NOT_FOUND_ERROR, e.getClass().getSimpleName());
            }
            catch (IOException e) {
                log.error("Failed to read Mt Wilson Root CA certificate file. ", e);
                throw new MSException(ErrorCode.MS_ROOT_CA_CERT_READ_ERROR, e.getClass().getSimpleName());
            }
            catch (Exception e) {
                log.error("Error during retrieval of root certificate CA chain. ", e);            
                throw new MSException(ErrorCode.MS_ROOT_CA_CERT_ERROR, e.getClass().getSimpleName());
            }
        } else if ("saml".equals(locator.id)) {
            try {
                String certFile = MSConfig.getConfiguration().getString("mtwilson.saml.certificate.file"); 
                if( certFile != null && !certFile.startsWith(File.separator) ) {
                    certFile = "/etc/intel/cloudsecurity/" + certFile; 
                }
                if(certFile != null) {
                    File samlPemFile = new File(certFile);
                    FileInputStream in = new FileInputStream(samlPemFile);
                    caCert.setCertificate(IOUtils.toByteArray(in));
                    IOUtils.closeQuietly(in);
                } else {
                    throw new FileNotFoundException("Could not load Saml Cert location from config");
                }
            }
            catch (FileNotFoundException e) {
                log.error("SAML certificate file is not found.", e);
                throw new MSException(ErrorCode.MS_SAML_CERT_NOT_FOUND_ERROR, e.getClass().getSimpleName());
            }
            catch (IOException e) {
                log.error("Failed to read SAML certificate file.", e);
                throw new MSException(ErrorCode.MS_SAML_CERT_READ_ERROR, e.getClass().getSimpleName());
            }
            catch (Exception e) {
                log.error("Error during retrieval of SAML certificate chain.", e);
                throw new MSException(ErrorCode.MS_SAML_CERT_ERROR, e.getClass().getSimpleName());
            }      
        } else if ("privacy".equals(locator.id)) {
            try {
                String certFile = MSConfig.getConfiguration().getString("mtwilson.privacyca.certificate.list.file");
                 if( certFile != null && !certFile.startsWith(File.separator) ) {
                    certFile = "/etc/intel/cloudsecurity/" + certFile; 
                }
                if(certFile != null) {
                    File privacyCaPemFile = new File(certFile); 
                    FileInputStream in = new FileInputStream(privacyCaPemFile);
                    caCert.setCertificate(IOUtils.toByteArray(in));
                    IOUtils.closeQuietly(in);
                } else  { 
                    throw new FileNotFoundException("Could not read Privacy CA cert file location from config");
                }
            }
            catch (FileNotFoundException e) {
                log.error("Privacy CA certificate file is not found.", e);
                throw new MSException(ErrorCode.MS_PRIVACYCA_CERT_NOT_FOUND_ERROR, e.getClass().getSimpleName());
            }
            catch (IOException e) {
                log.error("Failed to read Privacy CA certificate file.", e);
                throw new MSException(ErrorCode.MS_PRIVACYCA_CERT_READ_ERROR, e.getClass().getSimpleName());
            }
            catch (Exception e) {
                log.error("Error during retrieval of Privacy CA certificate chain.", e);
                throw new MSException(ErrorCode.MS_PRIVACYCA_CERT_ERROR, e.getClass().getSimpleName());
            }
            
        } else if ("tls".equals(locator.id)) {
            try {
                String certFile = MSConfig.getConfiguration().getString("mtwilson.tls.certificate.file");
                if( certFile != null && !certFile.startsWith(File.separator) ) {
                    certFile = "/etc/intel/cloudsecurity/" + certFile; 
                }
                if(certFile != null) {
                    if( certFile.endsWith(".pem") ) {
                        File tlsPemFile = new File(certFile);
                        FileInputStream in = new FileInputStream(tlsPemFile);
                        caCert.setCertificate(IOUtils.toByteArray(in));
                        IOUtils.closeQuietly(in);
                    }
                    if( certFile.endsWith(".crt") ) {
                        File tlsPemFile = new File(certFile);
                        FileInputStream in = new FileInputStream(tlsPemFile);
                        caCert.setCertificate(IOUtils.toByteArray(in));
                        IOUtils.closeQuietly(in);
                    }
                    throw new FileNotFoundException("Certificate file is not in .pem or .crt format");
                }else{
                    throw new FileNotFoundException("Could not obtain TLS cert chain location from config");
                }

            }
            catch (FileNotFoundException e) {
                log.error("Server SSL certificate file is not found.", e);
                throw new MSException(ErrorCode.MS_SSL_CERT_NOT_FOUND_ERROR, e.getClass().getSimpleName());
            }
            catch (IOException e) {
                log.error("Failed to read server SSL certificate file.", e);
                throw new MSException(ErrorCode.MS_SSL_CERT_READ_ERROR, e.getClass().getSimpleName());
            }
            catch (Exception e) {
                log.error("Error during retrieval of SSL CA chain.", e);
                throw new MSException(ErrorCode.MS_SSL_CERT_ERROR, e.getClass().getSimpleName());
            }   
        }
        return caCert;
    }

    @Override
    public void store(CaCertificate item) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void create(CaCertificate item) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void delete(CaCertificateLocator locator) {
        throw new UnsupportedOperationException("not implemented");
    }

    @Override
    public void delete(CaCertificateFilterCriteria criteria) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    

}
