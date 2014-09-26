import re
from urllib import quote
from urlparse import urlparse
import time
import traceback

from bs4 import BeautifulSoup
from couchpotato.core.helpers.encoding import toUnicode, ss
from couchpotato.core.helpers.rss import RSS
from couchpotato.core.helpers.variable import tryInt, md5, isLocalIP
from couchpotato.core.logger import CPLog
from couchpotato.core.event import fireEvent
from couchpotato.core.media._base.providers.nzb.base import NZBProvider
from couchpotato.environment import Env
from dateutil.parser import parse
import requests
import xml.etree.ElementTree as XMLTree
from requests.packages.urllib3 import Timeout
from requests.packages.urllib3.exceptions import MaxRetryError

log = CPLog(__name__)


class Base(NZBProvider, RSS):

    urls = {
        'download': 'https://www.nzbindex.com/download/',
        'search': 'https://www.nzbindex.com/rss/?%s',
    }

    http_time_between_calls = 1  # Seconds
    
    def getCache(self, cache_key, url = None, **kwargs):

        use_cache = not len(kwargs.get('data', {})) > 0 and not kwargs.get('files')

        if use_cache:
            cache_key_md5 = md5(cache_key)
            cache = Env.get('cache').get(cache_key_md5)
            if cache:
                if not Env.get('dev'): log.debug('Getting cache %s', cache_key)
                return cache

        if url:
            try:

                cache_timeout = 300
                if 'cache_timeout' in kwargs:
                    cache_timeout = kwargs.get('cache_timeout')
                    del kwargs['cache_timeout']

                data = self.urlopen(url, **kwargs)
                if data and cache_timeout > 0 and use_cache:
                    self.setCache(cache_key, data, timeout = cache_timeout)
                return data
            except:
                if not kwargs.get('show_error', True):
                    raise

                log.debug('Failed getting cache: %s', (traceback.format_exc(0)))
                return ''
    
    # http request
    def urlopen(self, url, timeout = 30, data = None, headers = None, files = None, show_error = True, stream = False):
        url = quote(ss(url), safe = "%/:=&?~#+!$,;'@()*[]")

        if not headers: headers = {}
        if not data: data = {}

        # Fill in some headers
        parsed_url = urlparse(url)
        host = '%s%s' % (parsed_url.hostname, (':' + str(parsed_url.port) if parsed_url.port else ''))

        headers['Referer'] = headers.get('Referer', '%s://%s' % (parsed_url.scheme, host))
        headers['Host'] = headers.get('Host', None)
        headers['User-Agent'] = headers.get('User-Agent', self.user_agent)
        headers['Accept-encoding'] = headers.get('Accept-encoding', 'gzip')
        headers['Connection'] = headers.get('Connection', 'keep-alive')
        headers['Cache-Control'] = headers.get('Cache-Control', 'max-age=0')

        r = Env.get('http_opener')

        # Don't try for failed requests
        if self.http_failed_disabled.get(host, 0) > 0:
            if self.http_failed_disabled[host] > (time.time() - 900):
                log.info2('Disabled calls to %s for 15 minutes because so many failed requests.', host)
                if not show_error:
                    raise Exception('Disabled calls to %s for 15 minutes because so many failed requests')
                else:
                    return ''
            else:
                del self.http_failed_request[host]
                del self.http_failed_disabled[host]

        self.wait(host)
        status_code = None
        try:

            kwargs = {
                'headers': headers,
                'data': data if len(data) > 0 else None,
                'timeout': timeout,
                'files': files,
                'verify': False, #verify_ssl, Disable for now as to many wrongly implemented certificates..
                'stream': stream,
            }
            method = 'post' if len(data) > 0 or files else 'get'

            num_retries = self.conf('num_retries', default = 10)
            retry_wait = self.conf('retry_wait', default = 3)
            retry = 0
            while True:
                log.info('Opening url: %s %s, data: %s', (method, url, [x for x in data.keys()] if isinstance(data, dict) else 'with data'))
                response = r.request(method, url, **kwargs)
    
                status_code = response.status_code
                if response.status_code == requests.codes.ok:
                    data = response if stream else response.content
                    break
                else:
                    if retry < num_retries:
                        log.info('Retry %s from %s...', (str(retry + 1), str(num_retries)))
                        retry += 1
                        time.sleep(retry_wait)
                    else:
                        log.error('Max retries reached!')
                        response.raise_for_status()
                        break

            self.http_failed_request[host] = 0
        except (IOError, MaxRetryError, Timeout):
            if show_error:
                log.error('Failed opening url in %s: %s %s', (self.getName(), url, traceback.format_exc(0)))

            # Save failed requests by hosts
            try:

                # To many requests
                if status_code in [429]:
                    self.http_failed_request[host] = 1
                    self.http_failed_disabled[host] = time.time()

                if not self.http_failed_request.get(host):
                    self.http_failed_request[host] = 1
                else:
                    self.http_failed_request[host] += 1

                    # Disable temporarily
                    if self.http_failed_request[host] > 5 and not isLocalIP(host):
                        self.http_failed_disabled[host] = time.time()

            except:
                log.debug('Failed logging failed requests for %s: %s', (url, traceback.format_exc()))

            raise

        self.http_last_use[host] = time.time()

        return data
            
    def getRSSData(self, url, item_path = 'channel/item', **kwargs):

        cache_key = md5(url)
        data = self.getCache(cache_key, url, **kwargs)

        if data and len(data) > 0:
            try:
                data = XMLTree.fromstring(data)
                return self.getElements(data, item_path)
            except:
                try:
                    data = XMLTree.fromstring(ss(data))
                    return self.getElements(data, item_path)
                except:
                    log.error('Failed to parsing %s: %s', (self.getName(), traceback.format_exc()))

        return []

    def _search(self, media, quality, results):

        nzbs = self.getRSSData(self.urls['search'] % self.buildUrl(media, quality))

        for nzb in nzbs:

            enclosure = self.getElement(nzb, 'enclosure').attrib
            nzbindex_id = int(self.getTextElement(nzb, "link").split('/')[4])

            title = self.getTextElement(nzb, "title")

            match = fireEvent('matcher.parse', title, parser='usenet', single = True)
            if not match.chains:
                log.info('Unable to parse release with title "%s"', title)
                continue

            # TODO should we consider other lower-weight chains here?
            info = fireEvent('matcher.flatten_info', match.chains[0].info, single = True)

            release_name = fireEvent('matcher.construct_from_raw', info.get('release_name'), single = True)

            file_name = info.get('detail', {}).get('file_name')
            file_name = file_name[0] if file_name else None

            title = release_name or file_name

            # Strip extension from parsed title (if one exists)
            ext_pos = title.rfind('.')

            # Assume extension if smaller than 4 characters
            # TODO this should probably be done a better way
            if len(title[ext_pos + 1:]) <= 4:
                title = title[:ext_pos]

            if not title:
                log.info('Unable to find release name from match')
                continue

            try:
                description = self.getTextElement(nzb, "description")
            except:
                description = ''

            def extra_check(item):
                if '#c20000' in item['description'].lower():
                    log.info('Wrong: Seems to be passworded: %s', item['name'])
                    return False

                return True

            results.append({
                'id': nzbindex_id,
                'name': title,
                'age': self.calculateAge(int(time.mktime(parse(self.getTextElement(nzb, "pubDate")).timetuple()))),
                'size': tryInt(enclosure['length']) / 1024 / 1024,
                'url': enclosure['url'],
                'detail_url': enclosure['url'].replace('/download/', '/release/'),
                'description': description,
                'get_more_info': self.getMoreInfo,
                'extra_check': extra_check,
            })

    def getMoreInfo(self, item):
        try:
            if '/nfo/' in item['description'].lower():
                nfo_url = re.search('href=\"(?P<nfo>.+)\" ', item['description']).group('nfo')
                full_description = self.getCache('nzbindex.%s' % item['id'], url = nfo_url, cache_timeout = 25920000)
                html = BeautifulSoup(full_description)
                item['description'] = toUnicode(html.find('pre', attrs = {'id': 'nfo0'}).text)
        except:
            pass


config = [{
    'name': 'nzbindex',
    'groups': [
        {
            'tab': 'searcher',
            'list': 'nzb_providers',
            'name': 'nzbindex',
            'description': 'Free provider, less accurate. See <a href="https://www.nzbindex.com/">NZBIndex</a>',
            'wizard': True,
            'icon': 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAo0lEQVR42t2SQQ2AMBAEcUCwUAv94QMLfHliAQtYqIVawEItYAG6yZFMLkUANNlk79Kbbtp2P1j9uKxVV9VWFeStl+Wh3fWK9hNwEoADZkJtMD49AqS5AUjWGx6A+m+ARICGrM5W+wSTB0gETKzdHZwCEZAJ8PGZQN4AiQAmkR9s06EBAugJiBoAAPFfAQcBgZcIHzwA6TYP4JsXeSg3P9L31w3eksbH3zMb/wAAAABJRU5ErkJggg==',
            'options': [
                {
                    'name': 'enabled',
                    'type': 'enabler',
                    'default': True,
                },
                {
                    'name': 'extra_score',
                    'advanced': True,
                    'label': 'Extra Score',
                    'type': 'int',
                    'default': 0,
                    'description': 'Starting score for each release found via this provider.',
                },
                {
                    'name': 'num_retries',
                    'advanced': True,
                    'label': 'Number of retries',
                    'type': 'int',
                    'default': 10,
                    'description': 'The number of retries on connection error (typical 503).',
                },
                {
                    'name': 'retry_wait',
                    'advanced': True,
                    'label': 'Retry Wait',
                    'type': 'int',
                    'default': 3,
                    'description': 'The number of seconds to wait for retry.',
                }
            ],
        },
    ],
}]
