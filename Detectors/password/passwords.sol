//Variable names (password, pass, pwd) are based on sonar secret https://github.com/Skyscanner/sonar-secrets/blob/master/java/src/main/java/org/sonar/skyscanner/java/checks/Passwords.java
//Author: adeptex - github.com/adeptex (skyscanner)

pragma solidity ^0.8.18;

contract Passwords {
     string password; 
     string pass;
     string pwd;
     string key;
     string value;
    
    // Hardcoded passwords stored in variables 'password', 'pass', 'pwd' etc
    function usePassword() external {
        password = "password@123";
        pass = "uta@2023";
        pwd = "abc#765";
        key = "safePass";
    }

    function doesNotUsePassword(string memory p) external {
        value = p;
    }
}