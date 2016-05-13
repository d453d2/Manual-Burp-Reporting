# manual_Burp_Reporting
Another Burp extension that allows specific supporting data to be exported for the scanner issues into a csv.

# What does it do?
 - The extension provides the user the ability to select individual or multiple scan issues within the target issues tool.
 - Then migrates the supporting request and responses, along with their markers, finding title and URL to a CSV file.
 - This allows selected issues to by reported manually with payload markers.
* The request responses are base64 encoded to prevent payloads breaking anything during handling.

# Requirements
Ensure you have a standalone version of jython >= 2.7 installed.

Add this extension via the in-built Burpsuite Extender options:
 - Extender -> Extensions -> Add


# Usages:

How?

Fun part... Highlight any scan issues either singluarly or mulitple (e.g. hold cmd and select multiple issues.)  Send to 'manualReporter'
You will be able to see the issues being reported within the output tab in the extension tool.

Step 1: Load Extension

  - Pretty Straight forward, you will need a standalone Jython jar file.
  - Then use the Burp extender interface and load the 'manualReport_v1.0.py' extension.

Step 2: Finding Indentification

  - Test away until you want to create a new arbitrary finding.
  - Then right click on the request/response and select 'Generate Finding'
  - Or a scan issue picks up a problem you would like to report.

Step 3: Navigate to 'Target' - Issues

  - select the issues names you would like to report (multi or single), right click and select 'send to manualReporter'.

Step 4: Review details

  - details reported on will show up in the 'Extender' -> 'Extensions' -> 'Output' tab.

Step 4: Reporting

  - CSV file is created at the users root e.g. /Users/bob/.  called "Burp_Findings_Report.csv".
  - Handle the file however you like from here. ;)

Hope you enjoy using it.

[more work to come...]
