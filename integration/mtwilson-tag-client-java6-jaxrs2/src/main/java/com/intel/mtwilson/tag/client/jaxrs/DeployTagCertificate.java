/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.tag.client.jaxrs;

import java.net.URL;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author ssbangal
 */
public class DeployTagCertificate extends MtWilsonClient {
    
    Logger log = LoggerFactory.getLogger(getClass().getName());

    public DeployTagCertificate(URL url) {
        //super(url);
    }

    public DeployTagCertificate(Properties properties) throws Exception {
        super(properties);
    }
    
    /**
     * This function verifies whether the certificate was created for the specified host and deploy the
     * certificate on the host if there is a match. 
     * <p>
     * <i><u>Roles Needed:</u></i> AssetManagement
     * <p>
     * <i><u>Content type returned:</u></i>JSON/XML<br>
     * <p>
     * <i><u>Sample REST API call :</u></i><br>
     * <i>Method Type: POST</i><br>
     * https://192.168.1.101:8181/mtwilson/v2/rpc/deploy_tag_certificate
     * <p>
     * <i>Sample Input</i><br>
     * {"certificate_id":"a6544ff4-6dc7-4c74-82be-578592e7e3ba","host":"18=92.168.0.1"}
     * <p>
     * <i><u>Sample Output:</u></i><br>
     * None
     * <p>
     * @since Mt.Wilson 2.0
     */
    public void deployTagCertificate(String host, String selections) {
        return;
    }
        
}