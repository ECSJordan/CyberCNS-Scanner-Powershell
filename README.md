# CyberCNS-Scanner-Powershell

Powershell script that scans some stuff

## Usage

* Run the powershell file (make sure Set-ExecutionPolicy is set correctly)
* If you haven't input credentials yet, or you specify the `-RenewCredentials` flag, it will prompt for new API credentials.
* Credentials can be generated under your global view in CyberCNS > Users > Click the 3 dots and click "API Key".
* Once you input API credentials, it will save them locally as an encrypted string under `C:\CyberCNS\Credentials.txt`

## Todo:

* Add External Scan functionality (waiting CyberCNS team to add)
* Add option to save output from scans locally, currently only displays at runtime with an `Out-GridView` popup
