import re
import extractor

class deMailerMailRouting:

    def __init__(self, enabled: bool =True):

        self.enabled = enabled
        self.extractor = extractor.deMailerExtractor()
        self.counter = 1

    def mailRoute(self,received_froms) ->dict:
        
        _routingTable = {}
        #print("[+] Tracing 'Received: from' [Routing] ...")
        headerValue = received_froms
        if headerValue:     
            receivedFrom = self.extractor.extractReceivedFrom(headerValue)
            #print(receivedFrom)
            receivedBy = self.extractor.extractReceivedBy(headerValue)
            #print(receivedBy)
            receivedWith = self.extractor.extractReceivedWith(headerValue)
            #print(receivedWith)
            receivedDate = self.extractor.extractDate(headerValue)
            #print(receivedDate)
            smtpFrom = self.extractor.extractEmailSmtpFrom(headerValue)
            #print(smtpFrom)
            envelopFrom = self.extractor.extractEmailEnvelopeFrom(headerValue)
            #print(envelopFrom)

            _routingTable = {self.counter:{"Date":receivedDate,
                             "From":receivedFrom,
                             "By": receivedBy,
                             "With": receivedWith,
                             "SmtpFrom": smtpFrom,
                             "EnvelopeFrom": envelopFrom,
                            }}
            self.counter +=1

        return _routingTable
