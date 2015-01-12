url_diff
========

A tool (like diff) to show the differences between 2 URLs.

In my job I work with a lot of URLs, and often need to know which parameters (names and/or values) differ between the two.  I got fed up with "eye-balling" URLs to figure out the difference (esp. with different param orderings) so I'm developing a tool to do it for me.

enter url_diff
--------------

for example, what's different between these 2 URLs:
`http://example.com/?foo=bar&cake=lie&you=monster&beer=good&speech=free&breaking=bad`
`http://example.com/?&speech=free&beer=good&aperture=science&foo=bar&you=here&breaking=over`

    url_diff.py 'http://example.com/?foo=bar&cake=lie&you=monster&beer=good&speech=free&breaking=bad' \
      'http://example.com/?&speech=free&beer=good&aperture=science&foo=bar&you=here&breaking=over'
    breaking
    < bad
    > over

    cake
    < lie

    you
    < monster
    > here

    aperture
    > science

Also, you can use url_diff to enumerate the parameters of a single URL (which I
think is easier to read):

    python url_diff.py 'http://localhost/?param=val&readable=i%20think%20so'
    readable
    < i%20think%20so

    param
    < val

The help message should explain the rest:

    python url_diff.py --help

    usage: url_diff.py [-h] [--hostname] [--names] [--decode] [--quiet]
                       [--case_insensitive]
                       <left URL> [<right URL>]

    show the difference between 2 urls. Inspired by the unix utility diff

    positional arguments:
      <left URL>            URL to diff against. Logically handled as the left argurmnt of diff.
      <right URL>           URL to diff against. Logically handled as the right argurmnt of diff.

    optional arguments:
      -h, --help            show this help message and exit
      --hostname            also diff URL hostname
      --names, -n           only diff URL parameter names.
      --decode, -d          URL decode parameter names and values (if applicable).
                              Decoded params will be used for comparison and printing.
      --quiet, -q           suppress output and return non-zero if URLs differ.
      --case_insensitive, -i
                            Perform case insensitive diff. NOTE: this converts all input to lowercase.

    Currently this tool discards everything after '#' if it is present. see
    https://github.com/google/url_diff for more information.

Please keep in mind this is still in alpha, and it's currently a weekend project. Hope y'all find it useful too.

Currently it runs on versions of Python between 2.7 and 3.5
