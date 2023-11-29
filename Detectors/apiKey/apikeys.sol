//Variable (api,api23,google_key) names are based on sonar secret https://github.com/Skyscanner/sonar-secrets/blob/master/java/src/main/java/org/sonar/skyscanner/java/checks/APIKeys.java  Author: adeptex - github.com/adeptex (skyscanner)
//Source : https://api-key.me/index (Dummy API keys for variable name detetcion)
//AWS sample secrets taken from reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html 
pragma solidity ^0.8.18;

contract APIData {
    string api; 
    string google_key;
    string a;
    string b;
    string c;
    string d;
    string api23;
    bytes32 tempId;

    function useAPI() external {

        //Dummy API Keys generated from : https://api-key.me/index
        //for testing purpose

        api = string("d75441fc38f744439061754630373a63");
        api23 = string("a2ba819c35076f908b0822cd93c233d9");
        google_key = string("9415b6319fdc8f53200e1d6fe1d3d7e3");

        // AWS Client ID and secret key example fetched from 
        // https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
        a = "AKIAIOSFODNN7EXAMPLE"; // AWS Client ID
        b = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // AWS Secret key
    }

    function doesNotUseAPI(bytes32 t) external {
        tempId = t;
    }
}