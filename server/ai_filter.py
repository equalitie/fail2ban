"""
AIFilter

A fail2ban filter class which can use classifiers such as svm to decide
which IP to ban. However, it still support the normal Regex filters

AUTHORS: Vmon (C) 2012: Initial version

"""
import logging

from filter import FileFilter
#Learn to ban modules
from learn2ban.features import *
from learn2ban.features.learn2ban_feature import Learn2BanFeature
from learn2ban.ip_sieve import IPSieve
from learn2ban.train2ban import TrainingSet

from failmodel import FailModel, FailModelException


# Gets the instance of the logger.
logSys = logging.getLogger("fail2ban.filter")

class AIFilter(FileFilter):
    def __init__(self, jail, **kwargs):
        FileFilter.__init__(self, jail, **kwargs)

        #Initially we set the classifier equal to null
        self.__fail_classifiers = list()
        ## The ip siever:
       	self.__ip_sieve = IPSieve()
        self._build_available_feature_list()

    def _build_available_feature_list(self):
        """
        Search all the available feature class and stored them
        in a dictionary indexed by their names
        """
        self.__available_features={}
        self.__feature_list = list()
        for CurrentFeatureType in Learn2BanFeature.__subclasses__():
            self.__available_features[CurrentFeatureType.__name__] = CurrentFeatureType
            #This is wrong we need to update the list when we load the 
            #failmodel and the failModel class should keep a list for 
            #each classifier separately. But till bill adds the used features to
            #the fialmodel's base64 string we stick to this solution, assuming 
            #that all features are used
            self.addFeature(CurrentFeatureType.__name__)
    
    def addFailModel(self, value):
        """
        called by the jail to send the classifier model and the host regex
        to be used by this filter. For now only linear svm is supported. 
        The classifier comes pre-trained.

        INPUT:
            failmodel: only "svm.linear" is supported for now
        """
        try:
            fail_model = FailModel(value)
            self.__fail_classifiers.append(fail_model.getClassifier())
        except FailModelException, e:
            logSys.error(e)

    def delFailModel(self, index):
        try:
            del self.__fail_classifiers[index]
        except IndexError:
            logSys.error("Cannot remove fail model. Index %d is not "
						 "valid" % index)
    ### To be implemented
    def addFeature(self, feature_class_name):
        self.__feature_list.append(feature_class_name)

    def delFeature(self, feature_class_name):
        try:
            del self[self.__feature_list.find(feature_class_name)]

        except IndexError:
            logSys.error("Cannot remove %s from feature list." %feature_class_name)
        
    ##
    # Gets all the failure in the log file.
    #
    # Gets all the failure in the log file which are newer than
    # MyTime.time()-self.findTime. When a failure is detected, a FailTicket
    # is created and is added to the FailManager.
    def getFailures(self, filename):
        """
        Overriden version of getFailures, this is because almost all
        features necessary to classifies the type of requester are 
        statistical and can not be derived from single entry.
        """
        container = self.getFileContainer(filename)
        if container == None:
            logSys.error("Unable to get failures in " + filename)
            return False
        # Try to open log file.
        try:
            container.open()
        except Exception, e:
            logSys.error("Unable to open %s" % filename)
            logSys.exception(e)
            return False

        #because we also needs the log lines potentially for failModel, 
        #we store them in a list while reading them. 

        #It might be more efficient just to reset the file pointer, specially
        #now that all os caches disks aggressively
        #TODO: Consult bill on this issue, maybe we write a test program to 
        #to compare timing
        lines = list()
        while True:
            #Here we naively read all the lines one by one
            lines.append(container.readline())
            if (lines[-1] == "") or not self._isActive():
                # The jail reached the bottom or has been stopped
                break
            #if the filter has regex it will start bannig ips here
            self.processLineAndAdd(lines[-1])

        container.close()

        #Now we send the lines to feature aggrigation unit only
        #we the filter has ml capability
        if (self.__fail_classifiers):
            bad_ips = self._predict_failure(self._gather_all_features(lines))
            for bad_ip in bad_ips:
                self.addBannedIP(bad_ip)

        return True

    def _gather_all_features(self, log_lines):
        """
        Set the ip_sieve log equal to log_lines and compute features
        from feature list for all ips appearing in the logs.
        """
        self.__ip_sieve.set_log_lines(log_lines)
        self.__ip_sieve.parse_log()

        ip_feature_db = {}
        for cur_feature_name in self.__feature_list:
            cur_feature_tester = self.__available_features[cur_feature_name](self.__ip_sieve, ip_feature_db)
            cur_feature_tester.compute()

        return ip_feature_db

    def _predict_failure(self, ip_feature_db):
        """
        Turn the ip_feature_db into two dimensional array and feed it to
        all classifiers.
        """
        failList = list()
        ip_set = TrainingSet()
        for cur_ip in ip_feature_db:
            ip_set.add_ip(cur_ip, ip_feature_db[cur_ip])
            
        for fail_classifier in self.__fail_classifiers:
            bad_ip_prediction = fail_classifier.predict(ip_set._ip_feature_list)

            failList.extend([ip_set._ip_index[i] for i in range(0, len(bad_ip_prediction)) if bad_ip_prediction[i] == ip_set.BAD_TARGET])

        return failList
