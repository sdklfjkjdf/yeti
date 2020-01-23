from __future__ import unicode_literals
from datetime import timedelta

from plugins.analytics.public.process_url import ProcessUrl
from core.analytics import ScheduledAnalytics
from mongoengine import Q
import logging


class PropagatePhishing(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "PropagatePhishing",
        "description": "Propagates malware from URLs to hostnames",
    }

    ACTS_ON = 'Url'  # act on Urls only

    CUSTOM_FILTER = Q(tags__name="phishing")  # filter only tagged elements

    EXPIRATION = None

    @staticmethod
    def each(obj):
        t = obj.neighbors().values()
        logging.debug(t)
        n = obj.neighbors(neighbor_type="Hostname").values()
        if n:
            for link in n[0]:
                link[1].tag('phishing')
        else:
            h = ProcessUrl.each(obj)
            if h is not None:
                h.tag('phishing')
        n = obj.neighbors(neighbor_type="Ip").values()
        if n:
            for link in n[0]:
                link[1].tag('phishing')
        else:
            h = ProcessUrl.each(obj)
            if h is not None:
                h.tag('phishing')
