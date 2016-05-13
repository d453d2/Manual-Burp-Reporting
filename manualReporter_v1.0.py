# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IExtensionHelpers
from burp import IHttpRequestResponseWithMarkers
from burp import ITab
from burp import IMessageEditorController
from burp import ITextEditor
from burp import IHttpService
from burp import IScanIssue
from burp import IScannerListener
from array import array
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyEvent
from java.util import List
from javax.swing import (JMenuItem)
import java.util.List
import traceback

import csv
import os




class BurpExtender(IBurpExtender, IScannerListener, IContextMenuFactory, ActionListener, IMessageEditorController, ITab, ITextEditor, IHttpService, IScanIssue, IHttpRequestResponseWithMarkers):

    def __init__(self):
        self.menuItem = JMenuItem('send to manualReporter')
        self.menuItem.addActionListener(self)   

    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
    
        # keep a reference to our callbacks object (Burp Extensibility Feature)
        self._callbacks = callbacks   
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Manual Reporter")
        callbacks.registerContextMenuFactory(self)

        self._callbacks.registerScannerListener(self)

        print "[+] Manual Reporter Extension Loaded!"
        print "[-] by d453d2 - 2016"

        # create report file csv
        self.createReport()

        self.masterFindingsList = []


####### ------- NEW ------- #######


    def getSelectedScanIssues(self):

        issues = self.ctxMenuInvocation.getSelectedIssues()

        # parses currently selected finding to a string
        if len(issues) >= 1 : # one or more issues can be sent (cmd select for example within target...)

            for self.m in issues:

                #print self.m
                # burp.sfg@3b784b06 # type <type 'burp.sfg'>

                # add requestResponseWithMarkers to be global so can be included in scanIssue
                requestResponse = self.m.getHttpMessages()

                #print "RequestResponse: ", requestResponse

                # returns 
                l = array.tolist(requestResponse)
                #print l
                #print l[0]

                # if there is more than one request response to a finding...
                if len(l) > 1:
                    k = len(l)
                    q = 1
                    for r in l:

                        #call functionality to handle issues
                        self.processRequest(r, q, k)
                        q = q + 1
                        
                else:
                    k = ""
                    q = ""
                    #call functionality to handle issues
                    self.processRequest(l[0], q, k)



    def processRequest(self, requestResponse, multipartOne, MulitpartTwo):

        r = requestResponse

        # get request data and convert to string
        requestDetail = r.getRequest()

        fName = self.m.getIssueName() # retrive issue name
        print "[+] Finding Name: ", self.m.getIssueName()
        url = self._helpers.analyzeRequest(r).getUrl()
        print "[+] Finding sent to report: [%s] " % str(url)

        # GET request details & Markers
        requestMarkers = r.getRequestMarkers()
        reqMarkersParsed = self.parseMarkers(requestMarkers)

        requestData = self._helpers.bytesToString(requestDetail) # converts & Prints out the entire request as string  

        # GET response details & Markers
        responseDetail = r.getResponse()
        responseMarkers = r.getResponseMarkers()  
        resMarkersParsed = self.parseMarkers(responseMarkers)

        responseData = self._helpers.bytesToString(responseDetail) # converts & Prints out the entire request as string  


        # base64 encode requestresponses:
        enRequest = requestData.encode('base64','strict')
        enResponse = responseData.encode('base64','strict')


        # Handles issues with more than on request and response to the issue eg: 1/2, 2/2
        multipart = str(multipartOne) + "/" + str(MulitpartTwo)

        Cbuffer = ""
        # prepare to write out to file   
        finding = [fName, url, enRequest, reqMarkersParsed, enResponse, resMarkersParsed, multipart, Cbuffer]

        # write out to file
        self.report(finding)

        if multipartOne != "" :
            print "[!] Part %s added to report" % multipart

        else:
            print "[!] Finding added to report."
        



    # takes an array of markers and cycles through them to collect the int coordinates.
    def parseMarkers(self, markers):

        markersOut = []
        c = 0

        if len(markers) >= 1:
            for i in range(0, len(markers)):
                c = c + 1
                #print "[+] Marker Pair %s:" % str(c)
                start = markers[i][0]
                #print "[+] start: ", start
                end = markers[i][1]
                #print "[+] end: ", end
                setM = [c,start,end]
                markersOut.append(setM)

        return markersOut
    

    def report(self, finding):

        f = open(self.c, "a")
        report = csv.writer(f)
        report.writerow(finding)
        f.close()


    def createReport(self):

        # Until I work out a different way specify a path for the report here
        # uncomment to find out the path of the outfile 
        path = os.getcwd()
        # potential for date to add in to the name...
        outfile = "Burp_Findings_Report.csv"
        print "[+] Report Location:", str(path)+"/"+outfile
        report = str(path)+"/"+outfile
        self.c = report
        #clear report 
        c = open(self.c, "w")
        # # create report file csv
        # c_headers       = ["Request", \
        #                     "Request-Markers", \
        #                     "Response", \
        #                     "Response-Markers", \
        #                     "MultiRequest" \
        #                     ]
        # self.c.writerow(c_headers)  
        c.close()

        return self.c


# API hook...

    def getHttpMessages(self):

        return [self.m]


# Actions on menu click...

    def actionPerformed(self, actionEvent):
        print "*" * 60
        try:
            # When clicked!! 
            self.getSelectedScanIssues()

        except:
            tb = traceback.format_exc()
            print tb


# create Menu

    def createMenuItems(self, ctxMenuInvocation):
        self.ctxMenuInvocation = ctxMenuInvocation
        return [self.menuItem]
    


# Notes:

    # requestResponseMarkers are an array of one or more lists of none overlapping ints. may none or only one
    # responseMarkers:  [[I@532164c, [I@675a9cb5]
    # 
    #for i in responseMarkers:
    #    print "a: ", i
    # a:  array('i', [1901, 2005]) # first marker set
    # a:  array('i', [2424, 2534]) # second marker set
    #print "i: ", responseMarkers[0][0]
    # 1901
    #print "i: ", responseMarkers[0][1]
    # 2005
    #print "i: ", responseMarkers[1][0]
    # 2424
    #print "i: ", responseMarkers[1][1]
    # 2534










