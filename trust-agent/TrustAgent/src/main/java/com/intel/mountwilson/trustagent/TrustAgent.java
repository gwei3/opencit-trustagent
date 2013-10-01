/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mountwilson.trustagent;

import com.intel.mountwilson.common.*;
import com.intel.mountwilson.trustagent.commands.*;
import java.io.File;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.intel.mountwilson.trustagent.commands.daa.ChallengeResponseDaaCmd;
import com.intel.mountwilson.trustagent.commands.daa.CreateIdentityDaaCmd;
import com.intel.mountwilson.trustagent.commands.hostinfo.HostInfoCmd;
import com.intel.mountwilson.trustagent.data.TADataContext;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dsmagadX
 */
public class TrustAgent {

    static Logger log = LoggerFactory.getLogger(TrustAgent.class.getName());

    public TrustAgent() {
        TADataContext context = new TADataContext();
        try {
            File file = new File(context.getDataFolder());


            if (!file.isDirectory()) {
                file.mkdir();
                log.info("Data folder was not there created : " + context.getDataFolder());
            }


        } catch (Exception e) {
            log.error( "Error while creating data folder ", e);
        }

    }

    public boolean takeOwnerShip() {
        TADataContext context = new TADataContext();
        try {
            new TakeOwnershipCmd(context).execute();
        } catch (Exception e) {
            log.error( null, e);
            return false;
        }
        return true;
    }

    public String processRequest(String xmlInput) {
        if (xmlInput.contains("quote_request")) {
            log.info("Quote request received");
            return processQuoteRequestInput(xmlInput);
        } else if (xmlInput.contains("identity_request")) {
            return processIdentityRequestInput(xmlInput);
        } else if (xmlInput.contains("daa_challenge")) {
            return respondToDaaChallenge(xmlInput);
        } else if (xmlInput.contains("host_info")) {
            return hostInfo(xmlInput);
        } else {
            return generateErrorResponse(ErrorCode.UNSUPPORTED_OPERATION, xmlInput);
        }
    }

    private String processQuoteRequestInput(String xmlInput) {
        try {
            TADataContext context = new TADataContext();

            context.setNonce(getNonce(xmlInput));
            context.setSelectedPCRs(getSelectedPCRs(xmlInput));

            validateCertFile();

            new CreateNonceFileCmd(context).execute();
            new ReadIdentityCmd(context).execute();
            // Get the module information
            new GenerateModulesCmd(context).execute();
            new GenerateQuoteCmd(context).execute();
            new BuildQuoteXMLCmd(context).execute();

            return context.getResponseXML();

        } catch (TAException ex) {
            log.error( null, ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }
    }

    private String processIdentityRequestInput(String xmlInput) {
        try {
            TADataContext context = new TADataContext();

            if (TAConfig.getConfiguration().getBoolean("daa.enabled")) {
                new CreateIdentityDaaCmd(context).execute();
                new BuildIdentityXMLCmd(context).execute();
            } else {
                new CreateIdentityCmd(context).execute();
                new BuildIdentityXMLCmd(context).execute();
            }

            return context.getResponseXML();

        } catch (TAException ex) {
           log.error("Error in processIdentityRequestInput", ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }

    }

    private String respondToDaaChallenge(String xmlInput) {
        try {
            TADataContext context = new TADataContext();

            if (TAConfig.getConfiguration().getBoolean("daa.enabled")) {
                context.setDaaChallenge(getDaaChallenge(xmlInput));
                new ChallengeResponseDaaCmd(context).execute();
                context.setResponseXML("<daa_response><encoding>base64</encoding><content>" + Base64.encodeBase64String(context.getDaaResponse()) + "</content></daa_response>");
            } else {
                context.setResponseXML(generateErrorResponse(ErrorCode.ERROR, "DAA not enabled"));
            }

            return context.getResponseXML();

        } catch (TAException ex) {
            log.error( "Error in processIdentityRequestInput", ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }

    }

    public String generateErrorResponse(ErrorCode errorCode) {

        String responseXML =
                "<client_request> "
                + "<timestamp>" + new Date(System.currentTimeMillis()).toString() + "</timestamp>"
                + "<clientIp>" + CommandUtil.getHostIpAddress() + "</clientIp>"
                + "<error_code>" + errorCode.getErrorCode() + "</error_code>"
                + "<error_message>" + errorCode.getMessage() + "</error_message>"
                + "</client_request>";
        return responseXML;
    }

    public String generateErrorResponse(ErrorCode errorCode, String errorMsg) {

        String responseXML =
                "<client_request> "
                + "<timestamp>" + new Date(System.currentTimeMillis()).toString() + "</timestamp>"
                + "<clientIp>" + CommandUtil.getHostIpAddress() + "</clientIp>"
                + "<error_code>" + errorCode.getErrorCode() + "</error_code>"
                + "<error_message>" + errorCode.getMessage() + " " + errorMsg + "</error_message>"
                + "</client_request>";
        return responseXML;
    }

    private byte[] getDaaChallenge(String xmlInput) throws TAException {

        try {
            Pattern p = Pattern.compile("<daa_challenge>([^\"><]*?)</daa_challenge>"); // constrained regex from .* to [^\"><]
            Matcher m = p.matcher(xmlInput);
            m.find();
            String daaChallengeEncodedBase64 = m.group(1);
            log.info("DAA Challenge (base64): {0}", daaChallengeEncodedBase64);
            return Base64.decodeBase64(daaChallengeEncodedBase64);
        } catch (Exception e) {
            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot find DAA Challenge in the input xml: " + e.toString());
        }

    }

    private String getNonce(String xmlInput) throws TAException {

        try {
            Pattern p = Pattern.compile("<nonce>([^\"><]*?)</nonce>"); // constrained regex from .* to [^\"><]
            Matcher m = p.matcher(xmlInput);
            m.find();
            String nonce = m.group(1);
            log.info("Nonce {}", nonce);
            return nonce;
        } catch (Exception e) {
            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot find nonce in the input xml");
        }

    }

    private String getSelectedPCRs(String xmlInput) throws TAException {
        try {
            Pattern p = Pattern.compile("<pcr_list>([^\"><]*?)</pcr_list>"); // constrained regex from .* to [^\"><]
            Matcher m = p.matcher(xmlInput);
            m.find();
            String pcrList = m.group(1);

            return validateAndFormat(pcrList);
        } catch (Exception e) {
            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot find pcr_list in the input xml");
        }

    }

    private String validateAndFormat(String pcrList) throws TAException {
        String parts[] = pcrList.split(",");
        StringBuilder pcrInput = new StringBuilder("");
        Set<Integer> pcrs = new HashSet<Integer>();

        try {
            for (int i = 0; i < parts.length; i++) {
                if (parts[i].contains("-")) {

                    String[] subParts = parts[i].split("-");

                    int start = Integer.parseInt(subParts[0]);
                    int end = Integer.parseInt(subParts[1]);

                    if (start > end) {
                        throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("Start %d is greater than end %d", start, end));
                    }

                    for (int pcr = start; pcr <= end; pcr++) {
                        if (pcr >= 0 && pcr <= 23) {
                            pcrs.add(pcr);
                        }
                    }

                } else {
                    int pcr = Integer.parseInt(parts[i]);

                    if (pcr >= 0 && pcr <= 23) {
                        //pcrInput += (pcrInput.length() == 0) ? pcr : " " + pcr;
                        pcrs.add(pcr);
                    } else {
                        throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("PCR %d not in range 1-23", pcr));
                    }
                }
            }

            if (pcrs.isEmpty()) {
                throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("PCR list is empty.", pcrList));
            }

            for (Integer pcr : pcrs) {
                if (pcrInput.length() == 0) {
                    pcrInput.append(pcr.toString());
                } else {
                    pcrInput.append(" " + pcr);
                }

            }

        } catch (NumberFormatException e) {
            throw new TAException(ErrorCode.BAD_PCR_VALUES, String.format("PCR list [%s] contains a non number.", pcrList));
        }
        log.info("PCR List {}", pcrInput);
        return pcrInput.toString();
    }

    /**
     *
     * This belongs in a JUnit test class
     */
    /*
     * public static void main(String[] args) {
     *
     *
     * TADataContext context = new TADataContext();
     *
     * context.setNonce(new String(Base64.encodeBase64("asdf1234".getBytes())));
     * context.setSelectedPCRs("18 19");
     *
     * try {
     *
     * new CreateNonceFileCmd(context).execute(); new
     * CreateIdentityCmd(context).execute(); new
     * GenerateQuoteCmd(context).execute();
     *
     * new BuildQuoteXMLCmd(context).execute();
     *
     * log.info(context.getResponseXML());
     *
     * } catch (Exception ex) {
     * Logger.getLogger(TrustAgent.class.getName()).log(Level.SEVERE, null, ex);
     * } }
     *
     */
    private void validateCertFile() {
    }

    private String hostInfo(String xmlInput)  {
        try {
            TADataContext context = new TADataContext();
            new HostInfoCmd(context).execute();
            return getHostInfoXml(context);
        } catch (TAException ex) {
           log.error(null, ex);
            return generateErrorResponse(ex.getErrorCode(), ex.getMessage());
        }

    }

    private String getHostInfoXml(TADataContext context) {
        String responseXML =
                "<host_info>"
                + "<timeStamp>" + new Date(System.currentTimeMillis()).toString() + "</timeStamp>"
                + "<clientIp>" + CommandUtil.getHostIpAddress() + "</clientIp>"
                + "<errorCode>" + context.getErrorCode().getErrorCode() + "</errorCode>"
                + "<errorMessage>" + context.getErrorCode().getMessage() + "</errorMessage>"
                + "<osName>" + context.getOsName() + "</osName>"
                + "<osVersion> " + context.getOsVersion() + "</osVersion>"
                + "<biosOem>" + context.getBiosOem() + "</biosOem>"
                + "<biosVersion> " + context.getBiosVersion()+ "</biosVersion>"
                + "<vmmName>" + context.getVmmName() + "</vmmName>"
                + "<vmmVersion>" + context.getVmmVersion() + "</vmmVersion>"
                + "<processorInfo>" + context.getProcessorInfo() + "</processorInfo>"
                + "</host_info>";
        return responseXML;
        
        
    }
}
