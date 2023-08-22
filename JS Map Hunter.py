#
#  JS Map Hunter - Parse JavaScript source maps
#
#  Copyright (c) 2023 Manjesh S
#
from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from java.io import PrintWriter
from java.net import URL
from burp import IParameter
from java.util import ArrayList, List
from java.util.regex import Matcher, Pattern
import re
import json
import os
from javax import swing
from burp import IHttpRequestResponse
from java.awt import Font, Color
from threading import Thread
from array import array
from java.awt import EventQueue
from java.lang import Runnable
from thread import start_new_thread



class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

class BurpExtender(IBurpExtender, IScannerCheck, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("JS Map Hunter")

        callbacks.issueAlert("JS Map Hunter Passive Scanner enabled")

        stdout = PrintWriter(callbacks.getStdout(), True)
        stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerScannerCheck(self)
        self.initUI()
        self.callbacks.addSuiteTab(self)
        
        print ("JS Map Hunter loaded.")
        print ("Copyright (c) 2023 Manjesh S")
        self.outputTxtArea.setText("JS Map Hunter Running :" + "\n")

    def initUI(self):
        self.tab = swing.JPanel()

        # UI for Output
        self.outputLabel = swing.JLabel("JS Map Hunter Log:")
        self.outputLabel.setFont(Font("Tahoma", Font.BOLD, 14))
        self.outputLabel.setForeground(Color(255,102,52))
        self.logPane = swing.JScrollPane()
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(True)
        self.logPane.setViewportView(self.outputTxtArea)
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)



        # Layout
        layout = swing.GroupLayout(self.tab)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        self.tab.setLayout(layout)
      
        layout.setHorizontalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                )
            )
        )
        
        layout.setVerticalGroup(
            layout.createParallelGroup()
            .addGroup(layout.createParallelGroup()
                .addGroup(layout.createSequentialGroup()
                    .addComponent(self.outputLabel)
                    .addComponent(self.logPane)
                    .addComponent(self.clearBtn)
                )
            )
        )

    def getTabCaption(self):
        return "JS Map Hunter"

    def getUiComponent(self):
        return self.tab

    def clearLog(self, event):
          self.outputTxtArea.setText("JS Map Hunter Running :" + "\n" )

    
    def doPassiveScan(self, checkSourceMap):
        
        try:
            urlReq = checkSourceMap.getUrl()
            # check if JS file
            if ".js" in str(urlReq):
                host,port,protocol,method,headers,params,url,reqBodys,analyze_request = self.Get_RequestInfo(checkSourceMap)
                headers = [h.replace('.js HTTP', '.js.map HTTP').replace('.js?', '.js.map?') for h in headers]
                status_code,body = self.Get_ResponseInfo(checkSourceMap)
                if protocol == 'https':
                    is_https = True
                else:
                    is_https = False
                res = self.callbacks.makeHttpRequest(host, port, is_https, self.helpers.buildHttpMessage(headers,reqBodys))
                analyze_againRes = self.helpers.analyzeResponse(res)
                againResBodys = res[analyze_againRes.getBodyOffset():].tostring()
                try :
                    source_map = json.loads(againResBodys)
                except ValueError as e:
                    #self.outputTxtArea.append("\n" + "[-] Skipped " + str(urlReq))
                    return None
                version=int(source_map["version"])
                sources=source_map["sources"]
                sources_content=source_map["sourcesContent"]
                self.outputTxtArea.append("\n" + "[+] Version " + str(version) + " source map with "+str(len(sources))+" sources found:"+str(urlReq))
                issues = ArrayList()
                issues.add(ScanIssue(checkSourceMap, self.helpers))
                for index, path in enumerate(sources):
                    invalid = '^*":<>|?'
                    if path.startswith("../") or path.startswith("..\\"):
                        path = path[3:]
                        invalid = '^*":<>|?'
                    path = path.replace(" ^\.\/.*$", ".js")
                    for character in invalid:
                        path = path.replace(character, "")
                    self.outputTxtArea.append("\n" + "    Extracted: " + str(path))
                    try :
                        code = sources_content[index]
                    except IndexError as e:
                        continue
                    for index, header in enumerate(headers):
                        match = re.search(r"GET(.*) HTTP/", header)
                        if match:
                            headers[index] = header.replace(match.group(1), " /"+path)
                        else:
                            headers[index] = header
                    requestResponse = HttpRequestResponse(self.helpers.buildHttpService(host,port,protocol), self.helpers.buildHttpMessage(headers,reqBodys), code)
                    self.callbacks.addToSiteMap(requestResponse)
                return issues

            return None
        except UnicodeEncodeError:
            print ("Error in JS file analysis.")
        return None

        
    def consolidateDuplicateIssues(self, isb, isa):
        return -1

    def extensionUnloaded(self):
        print "JS Map Hunter unloaded"
        return
    def Get_ResponseInfo(self,baseRequestResponse):
        """
        extract response
        """
        analyze_response = self.helpers.analyzeResponse(baseRequestResponse.getResponse())
        status_code = analyze_response.getStatusCode()
        body =  baseRequestResponse.getResponse()[analyze_response.getBodyOffset():].tostring()

        return status_code,body
        
    def Get_RequestInfo(self,baseRequestResponse):
        """
        extract about service
        """
        service = baseRequestResponse.getHttpService()
        host = service.getHost()
        port = service.getPort()
        protocol = service.getProtocol()
        """
        extract request
        """
        analyze_request = self.helpers.analyzeRequest(service,baseRequestResponse.getRequest())
        reqBodys = baseRequestResponse.getRequest()[analyze_request.getBodyOffset():].tostring()
        url = analyze_request.getUrl()
        headers = analyze_request.getHeaders()
        method = analyze_request.getMethod()
        params = [i for i in analyze_request.getParameters() if i.getType() == IParameter.PARAM_URL]
        extract_params = '&'.join([('%s=%s' % (c.getName(),c.getValue())) for c in params ])

        return host,port,protocol,method,headers,extract_params,url,reqBodys,analyze_request
        


class ScanIssue(IScanIssue,ITab):
    def __init__(self, reqres, helpers):
        self.helpers = helpers
        self.reqres = reqres

    def getHost(self):
        self.outputTxtArea.append("\n" + "[+] Returned"+str(self.reqres.getHost()))
        return self.reqres.getHost()

    def getPort(self):
        return self.reqres.getPort()

    def getProtocol(self):
        return self.reqres.getProtocol()

    def getUrl(self):
        return self.reqres.getUrl()

    def getIssueName(self):
        return "Javascript Source map detected"

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return "Information" 

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return str("Client side Javascript source code can be combined, minified or compiled. A source map is a file that maps from the transformed source to the original source. Source map may help an attacker to read and debug Javascript.")

    def getRemediationBackground(self):
        return "Disable access to source maps files."

    def getIssueDetail(self):
        return str("Burp Scanner has analysed the following Javascript for Source map: <b>"
                      "%s</b><br><br><i>Check the sitemap to view Unpacked Javascript code.</i></b><br><br>" % (self.reqres.getUrl().toString()))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        reqss = [self.reqres]
        return reqss
        
    def getHttpService(self):
        return self.reqres.getHttpService()
        
class HttpRequestResponse(IHttpRequestResponse):
    def __init__(self, http_service, request, response):
        self._http_service = http_service
        self._request = request
        self._response = response

    def getComment(self):
        pass

    def getHighlight(self):
        pass

    def getHttpService(self):
        return self._http_service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

    def setComment(self, comment):
        pass

    def setHighlight(self, color):
        pass

    def setHttpService(self, http_service):
        pass

    def setRequest(self, message):
        pass

    def setResponse(self, message):
        pass        
        
if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
