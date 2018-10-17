/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.mountwilson.trustagent.commands;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.mountwilson.common.ErrorCode;
import com.intel.mountwilson.common.ICommand;
import com.intel.mountwilson.common.TAException;
import com.intel.mountwilson.trustagent.data.TADataContext;
import com.intel.mtwilson.util.exec.EscapeUtil;
import com.intel.mtwilson.util.exec.ExecUtil;
import com.intel.mtwilson.util.exec.Result;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.File;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author skaja
 */
public class GenerateModulesCmd implements ICommand {

    Logger log = LoggerFactory.getLogger(getClass().getName());
    private TADataContext context;

    public GenerateModulesCmd(TADataContext context) {
        this.context = context;
    }

    @Override
    public void execute() throws TAException {
        try {
            getXmlFromMeasureLog();

        } catch (Exception ex) {
            throw new TAException(ErrorCode.ERROR, "Error while getting Module details.", ex);
        }

    }

    /**
     * calls OAT script prepares XML from measureLog
     *
     * @author skaja
     */
    private void getXmlFromMeasureLog() throws TAException, IOException {
		String osName = System.getProperty("os.name");
		if (!osName.toLowerCase().contains("windows")) {
			log.debug("About to run the command: " + context.getMeasureLogLaunchScript());
			long startTime = System.currentTimeMillis();
			String outputPath = context.getMeasureLogXmlFile().getAbsolutePath();
			log.info("Module output file: {}", String.format("OUTFILE=%s", outputPath));
                        File outputFile = new File(outputPath);
                        if (!outputFile.exists()) {
                            Map<String, String> variables = new HashMap<>();
                            variables.put("OUTFILE", EscapeUtil.doubleQuoteEscapeShellArgument(outputPath));
                            CommandLine command = new CommandLine(EscapeUtil.doubleQuoteEscapeShellArgument(context.getMeasureLogLaunchScript().getAbsolutePath()));
                            Result result = ExecUtil.execute(command, variables);
                            if (result.getExitCode() != 0) {
                                log.error("Error running command [{}]: {}", command.getExecutable(), result.getStderr());
                                throw new TAException(ErrorCode.ERROR, result.getStderr());
                            }
                            log.debug("command stdout: {}", result.getStdout());
                            
                            long endTime = System.currentTimeMillis();
                            log.debug("measureLog.xml is created from txt-stat in Duration MilliSeconds {}", (endTime - startTime));
                        }
			if( outputFile.exists() ) {
                            String content = FileUtils.readFileToString(outputFile);
                            log.debug("Content of the XML file before getting modules: " + content);
                            
                            getModulesFromMeasureLogXml(content);
                            //outputFile.delete();  //why?
                        } else {
                            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot read module log");
			}
                } else {
			// In Windows, there is no script to prepare the xml with module measurements.
			// We only show 'tbootxm' module for PCR14. Read the measurement and prepare the xml content.
			File measurementFile = new File("C:\\Windows\\Logs\\MeasuredBoot\\measurement.sha1");
			if( measurementFile.exists() ) {
				String measurement = FileUtils.readFileToString(measurementFile);
				String content = "<measureLog><txt><modules><module><pcrBank>SHA1</pcrBank><pcrNumber>14</pcrNumber><name>tbootxm</name><value>" + measurement + "</value></module></modules></txt></measureLog>";
				
				log.debug("Content of the XML file after reading measurement {} ", content);
				getModulesFromMeasureLogXml(content);
			}
			else {
            log.info("No measurement file available for reading tbootxm measurement");
			//throw new TAException(ErrorCode.BAD_REQUEST, "Cannot read measurement file");
			}
		}
    }

    /**
     * Obtains <modules> tag under <txt> and add the string to TADataContext
     *
     * @author skaja
     */
    private void getModulesFromMeasureLogXml(String xmlInput) throws TAException {
        try {

            // Since the output from the script will have lot of details and we are interested in just the module section, we will
            // strip out the remaining data,
            Pattern PATTERN = Pattern.compile("(<modules>.*</modules>)");
            Matcher m = PATTERN.matcher(xmlInput);
            while (m.find()) {
                xmlInput = m.group(1);
            }
            // removes any white space characters from the xml string
            String moduleInfo = xmlInput.replaceAll(">\\s*<", "><");
            
            log.debug("Module information : " + moduleInfo);
            
            // If we have XML data, we we will have issues mapping the response to the ClientRequestType using JaxB unmarshaller. So,
            // we will encode the string and send it.
            moduleInfo = Base64.encodeBase64String(moduleInfo.getBytes());
            context.setModules(moduleInfo);
            

        } catch (Exception e) {
            throw new TAException(ErrorCode.BAD_REQUEST, "Cannot find modules in the input xml");
        }

    }
}
