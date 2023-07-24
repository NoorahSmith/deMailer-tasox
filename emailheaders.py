class deMailerMailHeaders():

    def __init__(self):

        self.email_headers = [
                                'ARC-Authentication-Results',
                                'Authenticated-By',
                                'Authentication-Results',
                                'Bcc',
                                'Cc',
                                'Content-Length',
                                'Content-Transfer-Encoding',
                                'Content-Type',
                                'DKIM-Signature',
                                'Date',
                                'Delivered-To',
                                'Feedback-ID',
                                'From',
                                'List-Id',
                                'List-Unsubscribe',
                                'Message-ID',
                                'Originating-IP',
                                'Received',
                                'Received-SPF',
                                'References',
                                'Reply-To',
                                'Return-Path',
                                'Sender',
                                'Subject',
                                'Thread-Topic',
                                'To',
                                'X-AntiAbuse',
                                'X-Authenticated-Sender',
                                'X-Authentication-Warning',
                                'X-BigFish',
                                'X-Distribution',
                                'X-Forefront-Antispam-Report',
                                'X-FOSE-spam',
                                'X-Google-Original-From',
                                'X-Identity',
                                'X-MS-Exchange-CrossTenant-AuthSource',
                                'X-MS-Exchange-Organization-AuthAs',
                                'X-MS-Exchange-Organization-AuthSource',
                                'X-MS-Has-Attach',
                                'X-Mailer',
                                'X-Originating-Email',
                                'X-Originating-IP',
                                'X-Originating-IP',
                                'X-OriginatorOrg',
                                'X-Received',
                                'X-Source',
                                'X-Source-Auth',
                                'X-Source-Sender',
                                'X-SourceIP',
                                'X-Spam',
                                'X-Spam-Report',
                                'X-Spam-Score',
                                'X-SpamScore',
                                'X-UIDL',
                                'x-pptenantcode'
                            ]

    def headers(self):
        
        headers = self.email_headers

        return headers