from __future__ import unicode_literals
from datetime import timedelta

from plugins.analytics.public.process_url import ProcessUrl
from core.analytics import ScheduledAnalytics
from mongoengine import Q


class PropagateC2(ScheduledAnalytics):

    default_values = {
        "frequency": timedelta(hours=1),
        "name": "PropagateC2",
        "description": "Propagates c2 from URLs to hostnames",
    }

    ACTS_ON = 'Url'  # act on Urls only

    CUSTOM_FILTER = Q(tags__name="c2")  # filter only tagged elements

    EXPIRATION = None

    @staticmethod
    def each(obj):
        n = obj.neighbors(neighbor_type="Hostname").values()
        if n:
            for link in n[0]:
                link[1].tag('c2')
        else:
            h = ProcessUrl.each(obj)
            if h is not None:
                h.tag('c2')
        n = obj.neighbors(neighbor_type="Ip").values()
        if n:
            for link in n[0]:
                link[1].tag('c2')
        else:
            h = ProcessUrl.each(obj)
            if h is not None:
                h.tag('c2')
