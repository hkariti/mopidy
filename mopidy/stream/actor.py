from __future__ import unicode_literals

import fnmatch
import logging
import re
import urlparse

import pykka

from mopidy import audio as audio_lib, backend, exceptions
from mopidy.audio import scan
from mopidy.models import Track, SearchResult

logger = logging.getLogger(__name__)
HOOKS = dict()

try:
    from mopidy_youtube.backend import YoutubeLibraryProvider

    youtube = YoutubeLibraryProvider(None)
    HOOKS['youtube'] = youtube.search
    logger.debug("mopidy_youtube detected, will resolve youtube http links through it")
except ImportError:
    logger.debug("mopidy_youtube isn't present, youtube http links won't work")

class StreamBackend(pykka.ThreadingActor, backend.Backend):
    def __init__(self, config, audio):
        super(StreamBackend, self).__init__()

        self.library = StreamLibraryProvider(
            backend=self, timeout=config['stream']['timeout'],
            blacklist=config['stream']['metadata_blacklist'])
        self.playback = backend.PlaybackProvider(audio=audio, backend=self)
        self.playlists = None

        self.uri_schemes = audio_lib.supported_uri_schemes(
            config['stream']['protocols'])


class StreamLibraryProvider(backend.LibraryProvider):
    def __init__(self, backend, timeout, blacklist):
        super(StreamLibraryProvider, self).__init__(backend)
        self._scanner = scan.Scanner(min_duration=None, timeout=timeout)
        self._blacklist_re = re.compile(
            r'^(%s)$' % '|'.join(fnmatch.translate(u) for u in blacklist))

    def lookup(self, uri):
        parsed_uri = urlparse.urlsplit(uri)
        if parsed_uri.scheme not in self.backend.uri_schemes:
            return []

        if self._blacklist_re.match(uri):
            logger.debug('URI matched metadata lookup blacklist: %s', uri)
            return [Track(uri=uri)]

        try:
            data = self._scanner.scan(uri)
            track = scan.audio_data_to_track(data)
        except exceptions.ScannerError as e:
            logger.warning('Problem looking up %s: %s', uri, e)
            track = Track(uri=uri)

        return [track]

    def search(self, query=None, uris=None):
        parsed_uri = urlparse.urlsplit(query['uri'][0])
        if 'youtube.com' in parsed_uri.netloc or 'youtu.be' in parsed_uri.netloc \
            and uris[0] in ['http:', 'https:']:
                logger.debug("youtube link, calling youtube hook")
                return HOOKS['youtube'](query, uris)
