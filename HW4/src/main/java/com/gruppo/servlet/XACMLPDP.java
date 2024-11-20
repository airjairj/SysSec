/*package com.gruppo.servlet;

import org.ow2.authzforce.core.pdp.api.*;
import org.ow2.authzforce.core.pdp.impl.*;

import java.nio.file.Path;
import java.nio.file.Paths;

public class XACMLPDP {
    public static void main(String[] args) throws Exception {
        Path policyFile = Paths.get("C:\\Users\\hp\\Documents\\Esami In Corso\\System Sec\\Homework\\SysSec\\HW4\\HW5\\XACML\\xacml-policy.xml");
        PdpEngineConfiguration config = PdpEngineConfiguration.getInstance(policyFile.toString());
        PdpEngine pdp = config.build();

        // Esempio di richiesta
        String request = "<Request xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" CombinePolicies=\"true\">...</Request>";
        DecisionRequest decisionRequest = pdp.newRequest(request);
        DecisionResult result = pdp.evaluate(decisionRequest);

        System.out.println("Decision: " + result.getDecision());
    }
}
*/