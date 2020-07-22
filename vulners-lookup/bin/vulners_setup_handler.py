import splunk.admin as admin


class ConfigApp(admin.MConfigHandler):
  """
  Set up supported arguments
  """
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['vulners_api_key']:
        self.supportedArgs.addOptArg(arg)

  def handleList(self, confInfo):
    confDict = self.readConf("vulners")
    if None != confDict:
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          if val in [None, '']:
            val = ''
          confInfo[stanza].append(key, val)
          
  """
  After user clicks Save on setup page, take updated parameters,
  normalize them, and save them somewhere
  """
  def handleEdit(self, confInfo):
    args = self.callerArgs
    
    if args.data['vulners_api_key'][0] in [None, '']:
      args.data['vulners_api_key'][0] = ''
        
    self.writeConf('vulners', 'setupentity', self.callerArgs.data)
      
# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
