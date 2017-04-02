/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mtwilson.trustagent.client.jaxrs;

import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.tls.policy.TlsConnection;
import com.intel.mtwilson.jaxrs2.client.MtWilsonClient;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.trustagent.model.VMAttestationRequest;
import com.intel.mtwilson.trustagent.model.VMAttestationResponse;
import com.intel.mtwilson.trustagent.model.*;
import java.security.cert.X509Certificate;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import org.apache.commons.lang.StringUtils;

/**
 *
 * @author ssbangal
 */
public class TrustAgentClient extends MtWilsonClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TrustAgentClient.class);
    
    public TrustAgentClient(Properties properties, TlsConnection tlsConnection) throws Exception {
        super(properties, tlsConnection);
    }
    
     /**
     * Retrieves the Attestation Identity Key (AIK) certificate for the host. The required content type can also be specified
     * as an extension in the URL.
     * @return AIK x509 certificate
     * @since Mt.Wilson 2.0
     * @mtwContentTypeReturned PKIX_CERT/X_PEM_FILE
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:1443/v2/aik
     * https://server.com:1443/v2/aik.pem
     * https://server.com:1443/v2/aik.cer
     * 
     * Headers:
     * Accept: application/pkix-cert
     * or
     * Accept: application/x-pem-file
     * 
     * Output:
     * X509Certificate certificate in DER format or PEM format:
     * -----BEGIN CERTIFICATE-----
     * MIIDMjCCAhqgAwIBAgIGAU92j4SVMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEG10d2lsc29u
     * LXBjYS1haWswHhcNMTUwODI4MjMwNjAxWhcNMjUwODI3MjMwNjAxWjAbMRkwFwYDVQQDExBtdHdp
     * bHNvbi1wY2EtYWlrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArRUrsziH8nIJWPtA
     * CAXbugYI9yX/KmwtG2vdBFCon+FcT6zidynaUtUqTLPmMigVEsWiEhbVxNDPr+rKponkjDmeSn/w
     * WGFp/dETtKLYLUTW1Aij7DFmz6+draAB6k4m0JcVvCM+Xevs2VG1kBOxC94GtKtO9ycLFzTGlxTJ
     * FlRkoyd4qM45O8Xc/qS3xF2gNLNqhWzzQNWG/rJXK1o8k/7EIcvW9tRvGTBj+STKZiAG/gomSY8b
     * 0avhrtOIgFeV8oYbolPu7RaxuPbfXBoEpw7fnDwiCowm9dxAOQpJ02ZP5cj4ZbVHWULcBL/gY4T6
     * AZvQ2EZAqRIJ3LX/7fsSewIDAQABo3wwejAdBgNVHQ4EFgQUW7eXsmNIQ4buvbJlWuOoTau3Pykw
     * DwYDVR0TAQH/BAUwAwEB/zBIBgNVHSMEQTA/gBRbt5eyY0hDhu69smVa46hNq7c/KaEfpB0wGzEZ
     * MBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpa4IGAU92j4SVMA0GCSqGSIb3DQEBBQUAA4IBAQCUgor4
     * oNnnqukBT0B8C+zAPUm0w0yrvxM8YmaAIodKOhFIF9OuR/gWzAi2lzxsGoaPKqYEeZFQpMlQ8AvK
     * fZj6tBK7iUy0zFcuMqdvwMhXX2h3ryaw0Qslspy7HY3CIX6Qck5G2zAJBlHBd7ZXLVWcoTWa56o1
     * mNqUhftOBLi+DlB8klD7Z6/Un+XVlBTk5uimgT42WF0XupHJrOF0tx767JcopZQSeYbdiugQEztz
     * IKmdGysVyg+7F7hkhrQfLZsohLJ54Zvgrq5+nKF0Rj2zzoImlPtYUKV5EnQm2+SsLxr3GP1flm6M
     * sHIC30ht3TBDoVw8vh80jxsu75afi4Al
     * -----END CERTIFICATE-----
     * </pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   X509Certificate aik = client.getAik();
     * </xmp></pre></div>
     */        
    public X509Certificate getAik() {
        log.debug("target: {}", getTarget().getUri().toString());
        X509Certificate aik = getTarget()
                .path("/aik")
                .request()
                .accept(CryptoMediaType.APPLICATION_PKIX_CERT)
                .get(X509Certificate.class);
        return aik;
    }

     /**
     * Retrieves the CA certificate that signed the Attestation Identity Key (AIK) certificate for the host. 
     * @return AIK CA x509 certificate
     * @since Mt.Wilson 2.0
     * @mtwContentTypeReturned PKIX_CERT/X_PEM_FILE
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:1443/v2/aik/ca
     * https://server.com:1443/v2/aik/ca.pem
     * https://server.com:1443/v2/aik/ca.cer
     * 
     * Headers:
     * Accept: application/pkix-cert
     * or
     * Accept: application/x-pem-file
     * 
     * Output:
     * X509Certificate certificate in DER format or PEM format:
     * -----BEGIN CERTIFICATE-----
     * MIICvTCCAaWgAwIBAgIGAU+KI+kQMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNVBAMTEG10d2lsc29u
     * LXBjYS1haWswHhcNMTUwOTAxMTgyMDUzWhcNMjUwODMxMTgyMDUzWjAAMIIBIjANBgkqhkiG9w0B
     * AQEFAAOCAQ8AMIIBCgKCAQEAqnT+nx5W0c3Hm5yFIfXYbaYi86wC1LDqqVCHRzeFlO07moZw1oV/
     * ucwF/LOmepouxWRI7RVRdTZD6KV52O+Iu2kIHZ1UXWNmL+9BrGWufvByZy1f3u08TGl7WSuKVWFK
     * UPsQ+5XITMaknZlK+ldog2VbyNNwvty8yo/mFx2fnVrMmDz03E+pE1zUyIgqKSomlyS+rGlAl8ZD
     * 1cKKiZc8ZCRh38lLGjTalRXPGCnOTi3uK/P7wut3yynJM1ZEr9Vc6QYxcX8O3vd/RIkF0GqPJrh+
     * Xu0hWUPy1Eviz85NsHnQ2nZ79VC0VS0nqLIPKg5uqIyohGgppK41KWvC545nAQIDAQABoyIwIDAe
     * BgNVHREBAf8EFDASgRBISVMgSWRlbnRpdHkgS2V5MA0GCSqGSIb3DQEBBQUAA4IBAQA6qJLucSWy
     * dFb0BPvlsyYYFSdjPaGAFWFwh/lbHYI1Ouy3jw34gmZIR0xTSI/96NA5KO17bzhzvKg9+nsPIS5I
     * 81GBiIaPc4HPAuqi21jBCI/LZQIC61P1R6/Tmzosm8NrRX+VVn+NmBVp2rXFtBb6BmBmyx7D7cNZ
     * b6+C6DQ+gg2PlU8qAjAzF0iQUqzELL8LIzIMtVDJYSdHe4kgyFom3mnBwfhpUmsnv0U2YAsdgcH5
     * +uZPD/+j3en5u8O5rNY15onq+2pFIxA/F29DwWCuOlF4orc9ejPv5hdVqsHjUR0zPPj87gLeHUbj
     * vDTmD6JzA3PbuypM/bFZrELA7oT0
     * -----END CERTIFICATE-----
     * </pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   X509Certificate aikCa = client.getAikCa();
     * </xmp></pre></div>
     */        
    public X509Certificate getAikCa() {
        log.debug("target: {}", getTarget().getUri().toString());
        X509Certificate aik = getTarget()
                .path("/aik/ca")
                .request()
                .accept(CryptoMediaType.APPLICATION_PKIX_CERT)
                .get(X509Certificate.class);
        return aik;
    }
    
     /**
     * Retrieves the BIOS, OS and Hypervison information from the host.  
     * @return HostInfo object having the details of the host.
     * @since Mt.Wilson 2.0
     * @mtwContentTypeReturned JSON/XML
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:1443/v2/host
     * https://server.com:1443/v2/host.json
     * 
     * Headers:
     * Accept: application/json
     * 
     * Output:
     * {
     *   "timestamp":1447060685640,
     *   "error_code":"OK",
     *   "error_message":"OK",
     *   "os_name":"Ubuntu",
     *   "os_version":"14.04",
     *   "bios_oem":"Intel Corp.",
     *   "bios_version":"S5500.86B.01.00.0065.070920141009",
     *   "vmm_name":"QEMU","vmm_version":"2.0.0",
     *   "processor_info":" C2 06 02 00 FF FB EB BF",
     *   "hardware_uuid":"9F9A9165-61EF-11E0-B0A5-001E671044D8"
     * }
     * </pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   HostInfo hostInfo = client.getHostInfo();
     * </xmp></pre></div>
     */        
    public HostInfo getHostInfo() {
        log.debug("target: {}", getTarget().getUri().toString());
        HostInfo hostInfo = getTarget()
                .path("/host")
                .request()
                .accept(MediaType.APPLICATION_JSON)
                .get(HostInfo.class);
        return hostInfo;
    }
    
    
     /**
     * Writes the 20 byte asset tag into NVRAM that would be extended to PCR 22 by tBoot during the boot process. 
     * @param tag value is 20 bytes base64-encoded
     * @param hardwareUuid is the hardware UUID of the target host
     * @since Mt.Wilson 2.0
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre>
     * https://server.com:1443/v2/tag
     * 
     * Headers:
     * Content-Type: application/json
     * 
     * Input:
     * { tag: "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=", hardware_uuid: "7a569dad-2d82-49e4-9156-069b0065b262" }
     * 
     * Output: N/A
     * </pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   //data = byte array of x509 certificate containing asset tags
     *   byte[] tag = Sha256Digest.digestOf(data).toByteArray();
     *   //Hardware UUID retrieved from dmidecode or host info API
     *   UUID hardwareUuid = UUID.valueOf("7a569dad-2d82-49e4-9156-069b0065b262");
     *   client.writeTag(tag, hardwareUuid);
     * </xmp></pre></div>
     */          
    public void writeTag(byte[] tag, UUID hardwareUuid) {
        TagWriteRequest tagWriteRequest = new TagWriteRequest();
        tagWriteRequest.setTag(tag);
        tagWriteRequest.setHardwareUuid(hardwareUuid);
        getTarget()
                .path("/tag")
                .request()
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.json(tagWriteRequest));
    }
    
     /**
     * Retrieves the AIK signed quote from TPM.  
     * @param nonce - The nonce value is 20 bytes base64-encoded. The client chooses the nonce. The trust agent will 
     * automatically extend its IP address to the nonce before using it in the quote. The extend operation is 
     * nonce1 = sha1( nonce0 || ip-address ) where nonce0 is the original input nonce (20 bytes) and nonce1 
     * is the extended nonce used in the TPM quote (20 bytes), and the ip-address is the 4-byte encoding of 
     * the IP address.
     * @param pcrs - List of PCRs for which the quote is needed.
     * @return TpmQuoteResponse object having the details of the current status of the TPM and its PCR values.
     * The output is base64-encoded in both XML and JSON output formats. 
     * @since Mt.Wilson 2.0
     * @mtwContentTypeReturned JSON/XML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre><xmp>
     * https://server.com:1443/v2/tpm/quote
     * https://server.com:1443/v2/tpm/quote.json
     * 
     * Headers:
     * Content-Type: application/json
     * Accept: application/json
     * 
     * Input:
     * {"nonce":"tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=","pcrs":[0,17,18,19]}
     * 
     * Output:
     * {
     *   "timestamp": 1491041233964,
     *   "client_ip": "10.219.35.174",
     *   "error_code": "0",
     *   "error_message": "OK",
     *   "aik":
     *      "MIICvTCCAaWgAwIBAgIGAVsn1gt3MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2
     *       lsc29uLXBjYS1haWswHhcNMTcwNDAxMDQ0NjMwWhcNMjcwNDAxMDQ0NjMwWjAAMIIBIjAN
     *       BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl2F+1B1OnHKdVMnPNLTtjJLxbXhQAVJEOf
     *       zUt7aFPKtrF/3C4+GvMJOr4PH4BeiD6L71u7LCDV1whnoP4BfoTmCtO+h6Nhnp803ZfZIr
     *       PeLd/Xi0jtw4ImBL0dvWS0D6/t7bnJ9skVGQXJDYLn2AFKMHJKb2gV7maNmX+ATdUO2yeA
     *       Yo5KpLZjxKRjJSiyMKQ4UFnVp5KlE6QNU/hOIssMiKCnj3w8B0EyLX2QO/D9ZGdeM38qfU
     *       IucT/nwXLzOAnJeo9DcNOVpEcNlsjBbPuneVUVHFOlc9Rhq+caCD2jKhS/7m2BhwC9jwXg
     *       E9nhRGKCxvEu1kmBXDbKouUd3gGQIDAQABoyIwIDAeBgNVHREBAf8EFDASgRBISVNfSWRl
     *       bnRpdHlfS2V5MA0GCSqGSIb3DQEBCwUAA4IBAQByU1NemOYTRzRNsEoJHe5GD7Ua1AG/5Q
     *       xw2lcuCZj3nNWsqB+b8ro+Bz5zU4+ZIqxeKepkus/9IIRrwaslvKHbl9GL5fPwUR2Sgkel
     *       tNpMxLsIXfEnHX+I44PC7B12/BuQ2IR4IRKotGCwX1DVQ02iDxiAakTXQGEffApqqVnBwK
     *       SGl256ZYVjq5SP/gbhG/nzPQSLcxVZYuRUr9wqmqXNhrzXz0eaPtFZBdykSCq7aYwy+zJB
     *       o3XZTXdNO6/G/os1BfFQ2irMwzxrxgND4c9TzmKiV6qBQJdN9lTeETLX9LhzJuldA2rAoe
     *       5TZJdaoKxk/qvb3UVg01K34QwIU0qt",
     *   "quote":
     *      "AAMBAA4AAABQfcukkmfKzTisSNbXYtrX3dmdxFLQqBk6zAmj5bSkEc2mhOSO8NQpgzZ/g5
     *       FPkz4QvlyZs146UmMsqa7CsKjsnmrsJlM9oz5/PHlxSzN9xlNeDh69RAIav+kZkN8ezOqb
     *       ajAtXXlx+tamtTcoSk6vzBzGqY84oHzV4IPcUYrQKlgp32GCQbgNR4SlR6BGTxtIZp3wVG
     *       FqdWSdAwi18+Wl/PWdlcILrgXQfvdYAkV7F/bcsAKGdsvQzj/08TNz5WcYr4LovI2oh/RM
     *       Xdr5p32Gr15uSgFVAB5oF75xpvXi0fP+aa6hey66rG6t4/k6nxGXkfX+TnfOBghFxCZqDN
     *       HBRztBXu78eWdtrlFQtOoajWqrlKa2ep5pup5Q60br1LQAEK9GqnhMNR7wzW82tql6Tvkz
     *       ArT1Ogm0TiQyjG9yVredxcaet962UGcB1KPeriJR",
     *   "event_log":
     *      "PG1lYXN1cmVMb2c+PHR4dD48dHh0U3RhdHVzPjI8L3R4dFN0YXR1cz48b3NTaW5pdERhdG
     *       FDYXBhYmlsaXRpZXM+MDAwMDAwMDA8L29zU2luaXREYXRhQ2FwYWJpbGl0aWVzPjxzaW5p
     *       dE1sZURhdGE+PHZlcnNpb24+ODwvdmVyc2lvbj48c2luaXRIYXNoPmUwNjQ0MjE3NzJkYT
     *       BjY2E1OWNlYTQ3ODAxYzJlZTVlNWMyYTE3NTg8L3Npbml0SGFzaD48bWxlSGFzaD45Nzc2
     *       NmE3OTY0NTQ4MGEzZDUzNTljOGEwZjU3OTU2NDhkNzdmM2M0PC9tbGVIYXNoPjxiaW9zQW
     *       NtSWQ+ZmZmZmZmZmYxNTA5MTQyMDA1YjAwMDAwMDAwMWZmZmZmZmZmZmZmZjwvYmlvc0Fj
     *       bUlkPjxtc2VnVmFsaWQ+MDAwMDAwMDAwMDAwMDAwMDwvbXNlZ1ZhbGlkPjxzdG1IYXNoPj
     *       AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA8L3N0bUhhc2g+PHBv
     *       bGljeUNvbnRyb2w+MDAwMDAwMDA8L3BvbGljeUNvbnRyb2w+PGxjcFBvbGljeUhhc2g+MD
     *       AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDwvbGNwUG9saWN5SGFz
     *       aD48cHJvY2Vzc29yU0NSVE1TdGF0dXM+MDAwMDAwMDA8L3Byb2Nlc3NvclNDUlRNU3RhdH
     *       VzPjxlZHhTZW50ZXJGbGFncz4wMDAwMDAwMDwvZWR4U2VudGVyRmxhZ3M+PC9zaW5pdE1s
     *       ZURhdGE+PG1vZHVsZXM+PG1vZHVsZT48cGNyTnVtYmVyPjE3PC9wY3JOdW1iZXI+PG5hbW
     *       U+dGJfcG9saWN5PC9uYW1lPjx2YWx1ZT5jMzQzODQ5N2ZkYTgyN2JlM2IzMjFjNTMwOWEy
     *       MDRmMGM5ZTUzOTQzPC92YWx1ZT48L21vZHVsZT48bW9kdWxlPjxwY3JOdW1iZXI+MTg8L3
     *       Bjck51bWJlcj48bmFtZT52bWxpbnV6PC9uYW1lPjx2YWx1ZT5lMTk2MzA4N2NkNTE5M2I4
     *       Y2ViYTI3ZGU1MWM0ZWY3ZTAyZTllMGE5PC92YWx1ZT48L21vZHVsZT48bW9kdWxlPjxwY3
     *       JOdW1iZXI+MTk8L3Bjck51bWJlcj48bmFtZT5pbml0cmQ8L25hbWU+PHZhbHVlPjJhMWU5
     *       ODE5ZDY2MWUzNDM0NGNiMmQ0N2U0ZTQ4YTFkNzU5M2NjY2I8L3ZhbHVlPjwvbW9kdWxlPj
     *       wvbW9kdWxlcz48L3R4dD48L21lYXN1cmVMb2c+Cg==",
     *   "selected_pcr_banks": "SHA1",
     *   "is_tag_provisioned": true,
     *   "asset_tag": "EagnSkRlbA+p7/FgiNH5ybn53yY="
     * }
     * </xmp></pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   //Nonce should be randomly generated
     *   byte[] nonce = "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=".getBytes();
     *   int[] pcrs = new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23});
     *   TpmQuoteResponse tpmQuote = client.getTpmQuote(nonce, pcrs);
     * </xmp></pre></div>
     */
    public TpmQuoteResponse getTpmQuote(byte[] nonce, int[] pcrs) {
        TpmQuoteRequest tpmQuoteRequest = new TpmQuoteRequest();
        tpmQuoteRequest.setNonce(nonce);
        tpmQuoteRequest.setPcrs(pcrs);
        log.debug("target: {}", getTarget().getUri().toString());
        TpmQuoteResponse tpmQuoteResponse = getTarget()
                .path("/tpm/quote")
                .request()
                .accept(MediaType.APPLICATION_XML)
                .post(Entity.json(tpmQuoteRequest), TpmQuoteResponse.class);
        return tpmQuoteResponse;
    }
    
    /**
     * Retrieves the AIK signed quote from TPM for specified PCR bank.  
     * @param nonce - The nonce value is 20 bytes base64-encoded. The client chooses the nonce. The trust agent will 
     * automatically extend its IP address to the nonce before using it in the quote. The extend operation is 
     * nonce1 = sha1( nonce0 || ip-address ) where nonce0 is the original input nonce (20 bytes) and nonce1 
     * is the extended nonce used in the TPM quote (20 bytes), and the ip-address is the 4-byte encoding of 
     * the IP address.
     * @param pcrs - List of PCRs for which the quote is needed.
     * @param pcrBank - TPM PCR bank to read from.
     * @return TpmQuoteResponse object having the details of the current status of the TPM and its PCR values.
     * The output is base64-encoded in both XML and JSON output formats. 
     * @since Mt.Wilson 2.0
     * @mtwContentTypeReturned JSON/XML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre><xmp>
     * https://server.com:1443/v2/tpm/quote
     * https://server.com:1443/v2/tpm/quote.json
     * 
     * Headers:
     * Content-Type: application/json
     * Accept: application/json
     * 
     * Input:
     * {"nonce":"tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=","pcrs":[0,17,18,19],"pcrbanks":"SHA1 SHA256"}
     * 
     * Output: See output of previous API call above
     * </xmp></pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   //Nonce should be randomly generated
     *   byte[] nonce = "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=".getBytes();
     *   int[] pcrs = new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23});
     *   String pcrBanks = "SHA1 SHA256"
     *   TpmQuoteResponse tpmQuote = client.getTpmQuote(nonce, pcrs, pcrBanks);
     * </xmp></pre></div>
     */
    public TpmQuoteResponse getTpmQuote(byte[] nonce, int[] pcrs, String pcrBank) {
        TpmQuoteRequest tpmQuoteRequest = new TpmQuoteRequest();
        tpmQuoteRequest.setNonce(nonce);
        tpmQuoteRequest.setPcrs(pcrs);
        tpmQuoteRequest.setPcrbanks(pcrBank);
        log.debug("target: {}", getTarget().getUri().toString());
        TpmQuoteResponse tpmQuoteResponse = getTarget()
                .path("/tpm/quote")
                .request()
                .accept(MediaType.APPLICATION_XML)
                .post(Entity.json(tpmQuoteRequest), TpmQuoteResponse.class);
        return tpmQuoteResponse;
    }
    
    /**
     * Retrieves the AIK signed quote from TPM for specified PCR bank.  
     * @param nonce - The nonce value is 20 bytes base64-encoded. The client chooses the nonce. The trust agent will 
     * automatically extend its IP address to the nonce before using it in the quote. The extend operation is 
     * nonce1 = sha1( nonce0 || ip-address ) where nonce0 is the original input nonce (20 bytes) and nonce1 
     * is the extended nonce used in the TPM quote (20 bytes), and the ip-address is the 4-byte encoding of 
     * the IP address.
     * @param pcrs - List of PCRs for which the quote is needed.
     * @param pcrBanks - TPM PCR banks to read from.
     * @return TpmQuoteResponse object having the details of the current status of the TPM and its PCR values.
     * The output is base64-encoded in both XML and JSON output formats. 
     * @since Mt.Wilson 2.0
     * @mtwContentTypeReturned JSON/XML
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <pre><xmp>
     * https://server.com:1443/v2/tpm/quote
     * https://server.com:1443/v2/tpm/quote.json
     * 
     * Headers:
     * Content-Type: application/json
     * Accept: application/json
     * 
     * Input:
     * {"nonce":"tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=","pcrs":[0,17,18,19]}
     * 
     * Output: See output of previous API call above
     * </xmp></pre>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   //Nonce should be randomly generated
     *   byte[] nonce = "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=".getBytes();
     *   int[] pcrs = new int[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23});
     *   String[] pcrBanks = {"SHA1", "SHA256"};
     *   TpmQuoteResponse tpmQuote = client.getTpmQuote(nonce, pcrs, pcrBanks);
     * </xmp></pre></div>
     */
    public TpmQuoteResponse getTpmQuote(byte[] nonce, int[] pcrs, String[] pcrBanks) {
        TpmQuoteRequest tpmQuoteRequest = new TpmQuoteRequest();
        tpmQuoteRequest.setNonce(nonce);
        tpmQuoteRequest.setPcrs(pcrs);
                
        tpmQuoteRequest.setPcrbanks(StringUtils.join(pcrBanks, " "));
        log.debug("target: {}", getTarget().getUri().toString());
        TpmQuoteResponse tpmQuoteResponse = getTarget()
                .path("/tpm/quote")
                .request()
                .accept(MediaType.APPLICATION_XML)
                .post(Entity.json(tpmQuoteRequest), TpmQuoteResponse.class);
        return tpmQuoteResponse;
    }

    /**
     * Retrieves the TPM binding key certificate.
     * @return X509Certificate object with the TPM binding key certificate.
     * @since Mt.Wilson 3.0
     * @mtwContentTypeReturned PKIX_CERT/X_PEM_FILE
     * @mtwMethodType GET
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     * https://server.com:1443/v2/binding-key-certificate
     * 
     * Headers:
     * Accept: application/pkix-cert
     * or
     * Accept: application/x-pem-file
     * 
     * Output:
     * X509Certificate binding key certificate in DER format or PEM format:
     * -----BEGIN CERTIFICATE-----
     * MIIEWDCCA0CgAwIBAgIJAI0Y5QIDB12/MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2ls
     * c29uLXBjYS1haWswHhcNMTcwMzMxMDcxOTAyWhcNMjcwMzI5MDcxOTAyWjAlMSMwIQYDVQQDDBpD
     * Tj1CaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
     * AJncMFEbw+MjmDIjc22RIb7s8aFeoyuGwJ+At7mE9NZgZjGQFM5mEgK7Ji4Gk189RFV4UlCXewcs
     * /XxWQv/5GHLwBi4g34Atrw3BuOQ7/S71lZikj5ib4KjUi4nfrKx49BAzipRcsrvAAbNoC1uRiexJ
     * mNnh2fIEGCI7s+QsQOgzMtwBbowfwPCTeRmLMPxqbdrQ4uCA/AA60e1drMgynOoGEtCtwPveGvuV
     * /Xhurp+uUvVmJ9iG+BomR1ymwIUPUIGBlC5r4udwl7QsaPU+jJvWeifZnvPI6orb2O6Z30FP6PEz
     * Mwkz467G7DxLuiZvXA7/Oly5Dva2UhxcKNnwuOkCAwEAAaOCAZMwggGPMA4GA1UdDwEB/wQEAwIF
     * IDBbBgdVBIEFAwIpBFABAQAAABQAAAAEAQAAAAEAAwABAAAADAAACAAAAAACAAAAAGMjQZMDCqTo
     * zatwSQyn9ssOnozzF0upQGO1CFViJssAuwn1lMw/xssAAAAAADCCAQ4GCFUEgQUDAikBBIIBADd8
     * ufyT7S4Uh6jWKom59eJ6llZqLmm4Kx94H1fkFSzcmz/+AOkmKJJ7PSVdJurIGHT5KNxu3sqdbc18
     * 2eJ/+1USq6tnkOwaD/vix/eKMm8fXg9esKkVcbFFEMTT+1PKV9vT+DftchsyeMikDGIeCquVJNsx
     * /8ee//TY785FBFNRUfUwUyGaZ2FjES1S2j+nN+dK2bAFwBVkf8Vi90XzzPagAX15qAJXUe4L0BYL
     * fuLbTw+XhG8kVtzaRNWV57zfDtBGAdKquCJfN40nIE8RunKHUPoWH2Y9zQkGeEcrcJl7fzfyzjyw
     * wC+T3SUurCs5TVmjrc7cqNhuxJtbJwHH/WMwDgYIVQSBBQMCKQIEAgADMA0GCSqGSIb3DQEBCwUA
     * A4IBAQCQ5TILvM2RIBVh54BjRi3kDZNcM3ZQBIligwp5r3cudbDYH4WdcHBuDumaR0f/DTE/9k3D
     * jPTd6KLhCqyPZAYaipeX1EGsr5S7FcTAjvE90sLvlTpnkVxhQNqmqWMCNYdk9iEz7QlL31WSxvmp
     * x4lDegVQwxcyI8set2KA5YM1xLGqfu8N6opYKMiuDM2/S2F1dCxir+Tz/J/ERESATwnexTkgzoyU
     * bap+RfegcAWuEiIzkcgTRbt7RwzhynjIzmusfWhoErKoZMaKelX23DOMuMt/8QEDVO8Q1WEg1+p0
     * EnkuguLRqs0CU92uZ8yQMSXHgCr7ExelyZem10UZJsrJ
     * -----END CERTIFICATE-----
     * </xmp></pre></div>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   X509Certificate bindingKey = client.getBindingKeyCertificate();
     * </xmp></pre></div>
    */
    public X509Certificate getBindingKeyCertificate() {
        log.debug("target: {}", getTarget().getUri().toString());
        X509Certificate aik = getTarget()
                .path("/binding-key-certificate")
                .request()
                .accept(CryptoMediaType.APPLICATION_PKIX_CERT)
                .get(X509Certificate.class);
        return aik;
    }
    
    /**
     * Retrieves a VM attestation status.
     * @param vmInstanceId - the orchestration engine instance ID.
     * @return VMAttestationResponse object containing the details of the VM attestation status.
     * @since Mt.Wilson 3.0
     * @mtwContentTypeReturned JSON
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     * https://server.com:1443/v2/vrtm/status
     * 
     * Headers:
     * Content-Type: application/json
     * Accept: application/json
     * 
     * Input:
     * {"vm_instance_id":"a222c422-714f-42bd-89c6-7042870c5784"}
     * 
     * Output:
     * {
     *   "vm_instance_id": "a222c422-714f-42bd-89c6-7042870c5784",
     *   "trust_status": true
     * }
     * </xmp></pre></div>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   String vmInstanceId = "a222c422-714f-42bd-89c6-7042870c5784";
     *   VMAttestationResponse vmAttestationStatus = client.getVMAttestationStatus(vmInstanceId);
     * </xmp></pre></div>
    */
    public VMAttestationResponse getVMAttestationStatus(String vmInstanceId) {        
        VMAttestationRequest vmAttestationRequest = new VMAttestationRequest();
        vmAttestationRequest.setVmInstanceId(vmInstanceId);
        log.debug("target: {}", getTarget().getUri().toString());

        VMAttestationResponse vmAttestationResponse = getTarget()
                .path("/vrtm/status")
                .request()
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.json(vmAttestationRequest), VMAttestationResponse.class);
        return vmAttestationResponse;
    }
    
    /**
     * Retrieves the complete VM attestation report.
     * @param obj - VMAttestationRequest object containing the 
     * @return VMQuoteResponse object containing the details of the VM attestation report including the following:
     * - Signed VM Quote having the nonce, vm instance id, and cumulative hash
     * - Signed Trust Policy
     * - Signing key certificate
     * - Measurement log
     * @since Mt.Wilson 3.0
     * @mtwContentTypeReturned JSON
     * @mtwMethodType POST
     * @mtwSampleRestCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     * https://server.com:1443/v2/vrtm/report
     * 
     * Headers:
     * Content-Type: application/json
     * Accept: application/json
     * 
     * Input:
     * {"vm_instance_id":"a222c422-714f-42bd-89c6-7042870c5784", "nonce":"tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k="}
     * 
     * Output:
     * {
     *   "vm_quote":
     *      "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Inllcy
     *       I/PjxWTVF1b3RlPjxub25jZT5jYWUwMmNkZTE4Y2ZkMjY3YTViM2RiZWVlNTMyYTQ1OWMy
     *       Y2MzZmE0PC9ub25jZT48dm1faW5zdGFuY2VfaWQ+YTIyMmM0MjItNzE0Zi00MmJkLTg5Yz
     *       YtNzA0Mjg3MGM1Nzg0PC92bV9pbnN0YW5jZV9pZD48ZGlnZXN0X2FsZz5zaGExPC9kaWdl
     *       c3RfYWxnPjxjdW11bGF0aXZlX2hhc2g+ZDgzMTQwMWZiY2QyZjg3NGMzZDE2ODViNzI2OW
     *       FiYThlNDJjM2RhMDAyMWIwZTk0MzAxYzg3NTM0MjMyM2Q4YTwvY3VtdWxhdGl2ZV9oYXNo
     *       PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZy
     *       MiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIEFsZ29yaXRobT0iaHR0
     *       cDovL3d3dy53My5vcmcvMjAwMS8xMC94bWwtZXhjLWMxNG4jIi8+PFNpZ25hdHVyZU1ldG
     *       hvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNyc2Et
     *       c2hhMSIvPjxSZWZlcmVuY2UgVVJJPSIiPjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3
     *       JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNp
     *       Z25hdHVyZSIvPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMD
     *       AxLzEwL3htbC1leGMtYzE0biMiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdv
     *       cml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNzaGExIi8+PERpZ2
     *       VzdFZhbHVlPlB6ODQ4U3BHaXRjZm1IVno0VTdadHRLNzRJYz08L0RpZ2VzdFZhbHVlPjwv
     *       UmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+QzR1ZnVSdjY0Ui96cj
     *       FSZXZiU2dWWFYzY1l5aGpGa3AxL3RCY3VTdFJodDZEcy9kV0lid3JZMk9URmI3L1JNT2Vz
     *       bTZNUjRjYTNqWVVzc0N5MHVaQ0tETTJGaGJvaXRRZWtna2pJSXhFSVBUQ2R3ZzJVcmZXY0
     *       xsQjBTVFBIRWE4R05lN0VBMnlldjRXZlc0V3k5NXpob0dlKzFnVWUrVHkyQm93WlVzSlhP
     *       blRDV1UxTHcxNXlsQWkzQmlLZkpEdjU3d1ZQK2tkRExmSi85OVpTR0t0WHhwZTI0bTlmMy
     *       tERDJEZnZsTnR6cmpzNUtHTGZpSmxmbkRMN2RwQ1cxVzRMZm05c0pscnpZcVFRYUpFbCto
     *       azRBOXNTY1dMU3l4TGNzUVdPdmJkdjZVR2VrSFZtRFNFclJZaTg5MnF6ZElTZ2hvaHpJWk
     *       dESTMzdmVEMGI1bWZBPT08L1NpZ25hdHVyZVZhbHVlPjxLZXlJbmZvPjxYNTA5RGF0YT48
     *       WDUwOUNlcnRpZmljYXRlPk1JSUVTRENDQXpDZ0F3SUJBZ0lKQUx0enl4OTFpMkRuTUEwR0
     *       NTcUdTSWIzRFFFQkN3VUFNQnN4R1RBWEJnTlYKQkFNVEVHMTBkMmxzYzI5dUxYQmpZUzFo
     *       YVdzd0hoY05NVGN3TkRBeE1EUTBOalF6V2hjTk1qY3dNek13TURRMApOalF6V2pBbE1TTX
     *       dJUVlEVlFRRERCcERUajFUYVdkdWFXNW5YMHRsZVY5RFpYSjBhV1pwWTJGMFpUQ0NBU0l3
     *       CkRRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFKdkdQZm5mcE1yemw5Um
     *       1hT1IxMmZ1SkE4YVIKeGZ0RmdENTlTTGRKclUzcTI5TVNweGRWZ2Mwb1lxUVBjdFpLK1ZG
     *       czZmOVBCekhGTWUraGVPN1ZrczA4dktFaApKUkVielBrdExZOEZtK0FRQkZPSVR1elpxek
     *       ZHZVpKTGFZZFUxdnI0RURqNExFbExSRk1WMldpandOSmZlMzB2Cmp4MExkOVZXT2poUkh0
     *       dFFlUUZKR0ZNVnZSYTVaR1FYVTRELzh2VFNZV3NnUDEvalB3dWlPd1NENEp4SEFuc1QKUT
     *       Jxc3g2dWwvcGhsR0w0SkZvb29LN0dZb05oemJhL1lKRkkybUI3K1BHQktqRGNWeEtOUVRB
     *       Qm5rS0ZkamdWMAptdEppQVYvQ0U4MVNjT1ZySmdIblRleE51R3REMDkwaHM2akJrbFhIMV
     *       l0ZkhJTDhEVkVoWXZEcHhRRUNBd0VBCkFhT0NBWU13Z2dGL01BNEdBMVVkRHdFQi93UUVB
     *       d0lHd0RCYkJnZFZCSUVGQXdJcEJGQUJBUUFBQUJBQUFBQUUKQVFBQUFBRUFBUUFDQUFBQU
     *       RBQUFDQUFBQUFBQ0FBQUFBRzQ0Z2xDMFpPVkl1TzZLY3pGcUZFZ0xrT2VZNHpZTAptRFoz
     *       WkxMNVNWS2RXd0JPYTF4eG02QUFBQUFBQURDQ0FRNEdDRlVFZ1FVREFpa0JCSUlCQUNzU2
     *       NzUHhMRWwxClBTcHNkNitJbUxqUW5EajdNek9ucEdBdWpZSTJ6cTJONHhNUEtKVi9JWDh6
     *       cnEwUUNZODlSbmpobVY4UUUyUmYKNi9XUFMrd0pNcksvLzR3NGlmSy80eEtUcWsxQmNvaU
     *       1wbjkwOVdnVDNZR0JNc29NWjZmdHdZUVE1TVkvQVB2bgo5TkFzdGw5NzVKS2lqeVJkWUtS
     *       RmpQY3NISFVrZk53RFhOQnV3R1Z4cjNZMWIxUTNOS3loaTlXYlc5YmJlUFZxCldBTkpab1
     *       NmZjBEbU9UdXBHODhxek0wUCt4OFAwTVZUZ2NmOFJkN3pGVHByZHFhelFuYk9NdERpVFhU
     *       allMV0sKV3V3TWdtenBNZk04ZlhKcFBqdE1xK2RUSXdsZms0ZmJmZ2lDTjI0K0M3ZURObn
     *       VoZWMxWUZTa0lVbEYrYm5ZYQp5WkhQMmFUZ3Zlc3dEUVlKS29aSWh2Y05BUUVMQlFBRGdn
     *       RUJBSERPRlgrNDBaRFE4azF3ejMzT3d3Qlk2Wi81CmtDaTZlNFo5QlNvZ0JMUTQvYWdwcU
     *       MyTzd4M1VkS2pIQ05vV0ZYVjdVY3BTVzdscitPOThIbkU0ZFFzNkptejAKeXdVRWFuZTBY
     *       WncwSFBwWmF2NmtJeTBpYVdUY1JpUzEyOEZNM3lNOU16dVorenNsS3dWK3pNRE9pRXIzMG
     *       RMegovWHMvQWwyQ3U2TzA0S2JpdzNUVHF6Ymo1b082WjR3bEFqN3JVWC82eDdPV2Y4dFBT
     *       dklHMlJIQXBIRmt1cm5iCkVPZnJRdmVYOHFXN3BubW96ZEM3MWpCbXpLTElFdzNNdk9uWV
     *       JnWXlSYXVYUVJWTXpYVHFJa040dktjeDlLYkQKRUpTditOUDljTm9XVk5lS29yZW9uMGts
     *       YTd4VHlEdlVsZUxGN3J0RDJHNnUzeklNOFg3YnIyQ1dnbDg9CjwvWDUwOUNlcnRpZmljYX
     *       RlPjwvWDUwOURhdGE+PC9LZXlJbmZvPjwvU2lnbmF0dXJlPjwvVk1RdW90ZT4=",
     *   "vm_trust_policy":
     *      "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48bnMyOlRydXN0UG9saW
     *       N5IHhtbG5zOm5zMj0ibXR3aWxzb246dHJ1c3RkaXJlY3Rvcjpwb2xpY3k6MS4yIiB4bWxu
     *       czpuczM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiIHhtbG5zOnhzPS
     *       JodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSI+PG5zMjpEaXJlY3Rvcj48bnMy
     *       OkN1c3RvbWVySWQ+YWRtaW48L25zMjpDdXN0b21lcklkPjwvbnMyOkRpcmVjdG9yPjxucz
     *       I6SW1hZ2U+PG5zMjpJbWFnZUlkPkMzOUY5NkY0LUQ1QUYtNDNGMC1BQjE3LTdENjU4MEJE
     *       NEQ5NjwvbnMyOkltYWdlSWQ+PG5zMjpJbWFnZUhhc2g+ZDgzMTQwMWZiY2QyZjg3NGMzZD
     *       E2ODViNzI2OWFiYThlNDJjM2RhMDAyMWIwZTk0MzAxYzg3NTM0MjMyM2Q4YTwvbnMyOklt
     *       YWdlSGFzaD48L25zMjpJbWFnZT48bnMyOkxhdW5jaENvbnRyb2xQb2xpY3k+TWVhc3VyZU
     *       FuZEVuZm9yY2U8L25zMjpMYXVuY2hDb250cm9sUG9saWN5PjxuczI6RW5jcnlwdGlvbj48
     *       bnMyOktleSBVUkw9InVyaSI+aHR0cDovL3Jrc2F2aW5vLWNpdC1jb250cm9sbGVyOjIwMD
     *       gwL3YxL2tleXMvZTlhMGE4NTktMjRhYi00NTRmLWEwNmMtMGJkZDAwYWM2OWZmL3RyYW5z
     *       ZmVyPC9uczI6S2V5PjxuczI6Q2hlY2tzdW0gRGlnZXN0QWxnPSJtZDUiPjVjODI2YjViOD
     *       dhN2U5YmEzYjYzOWI4NWZjYjA3ODE2PC9uczI6Q2hlY2tzdW0+PC9uczI6RW5jcnlwdGlv
     *       bj48bnMyOldoaXRlbGlzdCBEaWdlc3RBbGc9InNoYTI1NiI+PG5zMjpTeW1saW5rIFBhdG
     *       g9Ii9iaW4vYXNoIj5hMDkxMzRmZmEyOWJkMTAxZDc4NjViOGI2OGE3YzM5NjM3OWZmYjY2
     *       YjViNTQ5MGUwNTlkMzg5YWYzZjRkMDAzPC9uczI6U3ltbGluaz48bnMyOlN5bWxpbmsgUG
     *       F0aD0iL2Jpbi9hZGR1c2VyIj5lODI0OTVkOWVkZWRmMDc2MDYxM2FjYWZjNWFhZGM0MjUz
     *       ODE5MWFkODE3YzE0ODU3ZGFjNTMzNmFlZDEyNzcxPC9uczI6U3ltbGluaz48bnMyOlN5bW
     *       xpbmsgUGF0aD0iL2Jpbi9hZGRncm91cCI+ZWU5YTRkNTQ2MzMxYzNlMGE4OTU3YzkwNTY4
     *       MzIxNDA5NDY1ODBlOWIxOTgwNGY1MjdjOTc4YmYwMmRlNTQ4NjwvbnMyOlN5bWxpbms+PC
     *       9uczI6V2hpdGVsaXN0PjxTaWduYXR1cmUgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIw
     *       MDAvMDkveG1sZHNpZyMiPjxTaWduZWRJbmZvPjxDYW5vbmljYWxpemF0aW9uTWV0aG9kIE
     *       FsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvVFIvMjAwMS9SRUMteG1sLWMxNG4tMjAw
     *       MTAzMTUiLz48U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcm
     *       cvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxSZWZlcmVuY2UgVVJJPSIi
     *       PjxUcmFuc2Zvcm1zPjxUcmFuc2Zvcm0gQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy
     *       8yMDAwLzA5L3htbGRzaWcjZW52ZWxvcGVkLXNpZ25hdHVyZSIvPjwvVHJhbnNmb3Jtcz48
     *       RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bW
     *       xlbmMjc2hhMjU2Ii8+PERpZ2VzdFZhbHVlPnY5b1BVZHJNWVhMSFZyZ2RFSmVsalgzRFli
     *       VnNnaldjYVRZanU5eTM5bTQ9PC9EaWdlc3RWYWx1ZT48L1JlZmVyZW5jZT48L1NpZ25lZE
     *       luZm8+PFNpZ25hdHVyZVZhbHVlPm5OeHFORW5hWDMwYWRQbXZSbDJhNlliVzFHRjc1dUZJ
     *       WEVkQXh0dlpxdnc4eFRPRDZxWlBoejVxQlRXMGJFUGwxZW1VZjRzdFV6YlkKZHRET3BYbn
     *       BIT21SNzlvajF3TCt0MlN6ODB4ZmUxUmRBWjVWcFFhVytEMlpCWU0zdUs4V28xMUhKakdZ
     *       VitVYkhnMjNUaG1zTWRLeAptTHpOZ1loZktWb05hR2JVQjJxWkk3YTN3dThYSVdLem1BZV
     *       JQOGZDSXFrRTRYYUxSZ1RYTGg0NDdjV1hwc0pqdmVjOG1hN09hRjhhClNXbHpqS2NlRmNj
     *       NHhpcVhZU20yK3N4VGhkbEJWeHRCWXR0NUVuTk8rdjAzQmxCKy9KaW5wTFBmc3RkOEZFKz
     *       dGZHZBVkJ1UVFRZWQKN2J0Q3ZlYzJ2QWROcFRHUmQxR3Vhd0hJZWVMK3ZUR2JiK1RLclE9
     *       PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5U3ViamVjdE5hbW
     *       U+Q049bXR3aWxzb24sT1U9TXQgV2lsc29uLE89SW50ZWwsTD1Gb2xzb20sU1Q9Q0EsQz1V
     *       UzwvWDUwOVN1YmplY3ROYW1lPjxYNTA5Q2VydGlmaWNhdGU+TUlJRFl6Q0NBa3VnQXdJQk
     *       FnSUVTQkU1WFRBTkJna3Foa2lHOXcwQkFRc0ZBREJpTVFzd0NRWURWUVFHRXdKVlV6RUxN
     *       QWtHQTFVRQpDQk1DUTBFeER6QU5CZ05WQkFjVEJrWnZiSE52YlRFT01Bd0dBMVVFQ2hNRl
     *       NXNTBaV3d4RWpBUUJnTlZCQXNUQ1UxMElGZHBiSE52CmJqRVJNQThHQTFVRUF4TUliWFIz
     *       YVd4emIyNHdIaGNOTVRjd016STVNakkxTmpFMFdoY05NamN3TXpJM01qSTFOakUwV2pCaU
     *       1Rc3cKQ1FZRFZRUUdFd0pWVXpFTE1Ba0dBMVVFQ0JNQ1EwRXhEekFOQmdOVkJBY1RCa1p2
     *       YkhOdmJURU9NQXdHQTFVRUNoTUZTVzUwWld3eApFakFRQmdOVkJBc1RDVTEwSUZkcGJITn
     *       ZiakVSTUE4R0ExVUVBeE1JYlhSM2FXeHpiMjR3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVB
     *       CkE0SUJEd0F3Z2dFS0FvSUJBUURaOUt6WGE0YjByUjlrbkNTTGxLTnVaZTdDbUVsU3hyWH
     *       pNOEhwQmQybTNOODdRZGMwTlZienlVdzgKTkFaWGtGSC9CUFgzK1JkL2ZiZEdEcWNXVWlv
     *       UmR4bkkrbjFobDJ4bjVkNC94WlJnRmFUQ240Yzg4K3pCb09GcE9vT2JNTStaWTJoawpDQ3
     *       dRMkR0YS9oaDhSTldXV2dHTHp1Mi9TcFFnNGFWS0pHT2tBa3VZRXE4dEhwazlsdWsxdGxX
     *       R1lrbHN0aFByeTd5aFpEa1ExdGFWCkYvL3VaRFRwTTZTMFh6NmRRcHRZL3BSbENFVktCeW
     *       tqdkNReFVBOUFzUGpEK0J0T0FsM2ZsWGZyWjJsQkdTd1pWeFNsNU9BcVFzTUEKc3NjWURx
     *       NlcwdkVWWFJ0SUw4RkNHcEk4SXo4Tmp6SEdtNHR3TlFBdndHeTZUbGM1QUxqRmtnTUJBZ0
     *       1CQUFHaklUQWZNQjBHQTFVZApEZ1FXQkJSUldjZ0NmdHRoZ0s2OGswL1U5R2U0ZkRLMGJq
     *       QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFMKzQybmU2VG1KU0pjZ1NhCjRWbmhzRXc4VW
     *       pwQWFIaW5oSVRVQkYrYS9Gdzlkd05oUk42NkpsS1hPc2xPdGdVVGxFZnc2dUwxSHBFbE5O
     *       ZXIzdlFGYmNkYm16dTEKbE9sdVBYYmpoSXhabEJLMUcraW9GL09aMXhHYzZhRlNWMTRCUl
     *       NuaTBPSkhjMUxhOTkyejY1RFlib0lzamFLcHVHbmJVcW9OTmNoRwpONkZRbFl3Wk1hb213
     *       ZldySnhHcUo1OURHWWc4MG91WTVERnJaMVk5ekdROGRLWnFoQmdqeGhYNE4wNmdPd3U0SX
     *       VqSUlOdmd1d3VqCmhOeUpuWHo1bDhrQlBhUmhiTWFyUW14UFRGWHEyYTRtVUo4enJiRFph
     *       WjdMOHcrRU5VbU5kWTBmeWJHQ3pBbWVIQ2ZUdi9uY3YwV04KRGJqOGtnVXhmRCtiMjdQYk
     *       5FQkcrdz09PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWdu
     *       YXR1cmU+PC9uczI6VHJ1c3RQb2xpY3k+",
     *   "vm_measurements":
     *      "PD94bWwgdmVyc2lvbj0iMS4wIj8+CjxNZWFzdXJlbWVudHMgeG1sbnM9Im10d2lsc29uOn
     *       RydXN0ZGlyZWN0b3I6bWVhc3VyZW1lbnRzOjEuMiIgRGlnZXN0QWxnPSJzaGEyNTYiPgo8
     *       U3ltbGluayBQYXRoPSIvYmluL2FzaCI+YTA5MTM0ZmZhMjliZDEwMWQ3ODY1YjhiNjhhN2
     *       MzOTYzNzlmZmI2NmI1YjU0OTBlMDU5ZDM4OWFmM2Y0ZDAwMzwvU3ltbGluaz4KPFN5bWxp
     *       bmsgUGF0aD0iL2Jpbi9hZGR1c2VyIj5lODI0OTVkOWVkZWRmMDc2MDYxM2FjYWZjNWFhZG
     *       M0MjUzODE5MWFkODE3YzE0ODU3ZGFjNTMzNmFlZDEyNzcxPC9TeW1saW5rPgo8U3ltbGlu
     *       ayBQYXRoPSIvYmluL2FkZGdyb3VwIj5lZTlhNGQ1NDYzMzFjM2UwYTg5NTdjOTA1NjgzMj
     *       E0MDk0NjU4MGU5YjE5ODA0ZjUyN2M5NzhiZjAyZGU1NDg2PC9TeW1saW5rPgo8L01lYXN1
     *       cmVtZW50cz4=",
     *   "vm_quote_type": "XML_DSIG"
     * }
     * </xmp></pre></div>
     * @mtwSampleApiCall
     * <div style="word-wrap: break-word; width: 1024px"><pre><xmp>
     *   TrustAgentClient client = new TrustAgentClient(properties, new TlsConnection(url, tlsPolicy));
     *   VMAttestationRequest request = new VMAttestationRequest();
     *   request.setVmInstanceId("a222c422-714f-42bd-89c6-7042870c5784");
     *   request.setNonce("tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=");  //Should be randomly generated
     *   VMQuoteResponse vmAttestationReport = client.getVMAttestationReport(request);
     * </xmp></pre></div>
    */
    public VMQuoteResponse getVMAttestationReport(VMAttestationRequest obj) {
        
        log.debug("target: {}", getTarget().getUri().toString());
        VMQuoteResponse vmQuoteResponse = getTarget()
                .path("/vrtm/report")
                .request()
                .accept(MediaType.APPLICATION_JSON)
                .post(Entity.json(obj), VMQuoteResponse.class);
                
        return vmQuoteResponse;
    }
}
