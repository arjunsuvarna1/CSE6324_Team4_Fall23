//Source : https://stackoverflow.com/questions/62073437/how-to-make-an-api-call-in-solidity (API Key Structure)
//Author: Patrick Collins

pragma solidity ^0.8.18;

contract APIData {
    bytes32 api; 
    bytes32 google_key;
    bytes32 api1_key;
    bytes32 api23;
    bytes32 tempId;

    function useAPI() external {

        //API key fetched from https://stackoverflow.com/questions/62073437/how-to-make-an-api-call-in-solidity 
        //for testing purpose

        api = bytes32("c179a8180e034cf5a341488406c32827");
        api23 = bytes32("c179a8180e034cf5a341488406c32827");
        google_key = bytes32("c179a8180e034cf5a341488406c32827");
        
    }

    function doesNotUseAPI(bytes32 t) external {
        tempId = t;
    }
}