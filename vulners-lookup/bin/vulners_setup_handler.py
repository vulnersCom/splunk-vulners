import splunk.admin as admin

'''
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the configuration page.

      handleList method: lists configurable parameters in the configuration page
      corresponds to handleractions = list in restmap.conf

      handleEdit method: controls the parameters and saves the values 
      corresponds to handleractions = edit in restmap.conf

'''

class ConfigApp(admin.MConfigHandler):
  '''
  Set up supported arguments
  '''
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['vulners_api_key']:
        self.supportedArgs.addOptArg(arg)
        
  '''
  Read the initial values of the parameters from the custom file
      myappsetup.conf, and write them to the setup page. 

  If the app has never been set up,
      uses .../app_name/default/myappsetup.conf. 

  If app has been set up, looks at 
      .../local/myappsetup.conf first, then looks at 
  .../default/myappsetup.conf only if there is no value for a field in
      .../local/myappsetup.conf

  For boolean fields, may need to switch the true/false setting.

  For text fields, if the conf file says None, set to the empty string.
  '''

  def handleList(self, confInfo):
    confDict = self.readConf("vulners")
    if None != confDict:
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          if val in [None, '']:
            val = ''
          confInfo[stanza].append(key, val)
          
  '''
  After user clicks Save on setup page, take updated parameters,
  normalize them, and save them somewhere
  '''
  def handleEdit(self, confInfo):
    args = self.callerArgs
    
    if args.data['vulners_api_key'][0] in [None, '']:
      args.data['vulners_api_key'][0] = ''  

        
    '''
    Since we are using a conf file to store parameters, 
write them to the [setupentity] stanza
    in app_name/local/myappsetup.conf  
    '''
        
    self.writeConf('vulners', 'setupentity', self.callerArgs.data)
      
# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
