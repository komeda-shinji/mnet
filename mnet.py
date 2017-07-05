#!/usr/bin/python

'''
	MNet Suite
	mnet.py

	Michael Laforest
	mjlaforest@gmail.com

	Copyright (C) 2015 Michael Laforest

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

import sys
import getopt
import optparse
import datetime
import os

import mnetsuite

usgmsg = """
Usage:
	mnet.py graph -r <root IP>
	              -f <file> | -g <file>
	              [-d <max depth>]
	              [-c <config file>]
	              [-t <diagram title>]
	              [-C <catalog file>]

	mnet.py tracemac -r <root IP>
	                 -m <MAC Address>
	                 [-c <config file>]

	mnet.py config
"""

def print_syntax():
	print('Usage:\n'
			'  mnet.py graph -r <root IP>\n'
			'                -f <file> (in graphvis)\n'
			'                -g <file> (in GraphML)\n'
			'                [-d <max depth>]\n'
			'                [-c <config file>]\n'
			'                [-t <diagram title>]\n'
			'                [-C <catalog file>]\n'
			'\n'
			'  mnet.py tracemac -r <root IP>\n'
			'                   -m <MAC Address>\n'
			'                   [-c <config file>]\n'
			'\n'
			'  mnet.py config\n'
		)


def print_banner():
	print('MNet Suite v%s' % mnetsuite.__version__)
	print('Written by Michael Laforest <mjlaforest@gmail.com>')
	print('')


def main(argv):
	if (len(argv) < 1):
		print_banner()
		print_syntax()
		return

	mod = argv[0]
	if (mod == 'graph'):
		print_banner()
		graph(argv[1:])
	elif (mod == 'tracemac'):
		print_banner()
		tracemac(argv[1:])
	elif (mod == 'config'):
		generate_config()
	else:
		print_banner()
		print_syntax()


def graph(argv):
	opt_root_ip = []
	max_depth = 0

	graph = mnetsuite.mnet_graph()

	opt_dot = None
	opt_graphml = None
	opt_depth = 0
	opt_title = 'MNet Network Diagram'
	opt_conf = './mnet.conf'
	opt_catalog = None

        parser = optparse.OptionParser(usage=usgmsg)
	parser.add_option('-r', '--root',
                      action='append', dest='root_ip')
	parser.add_option('-f',
                      action='store', dest='dot')
	parser.add_option('-g',
                      action='store', dest='graphml')
	parser.add_option('-d',
                      action='store', dest='depth', type='int', default=0)
	parser.add_option('-t',
                      action='store', dest='title', default=opt_title)
	parser.add_option('-c',
                      action='store', dest='conf')
	parser.add_option('-C',
                      action='store', dest='catalog')

        parser.add_option('--layout',
                      action='store', dest='LayoutStyle', default='dot',
                      help='layout style for GraphML output '
                           '(dot|spring|circular|random|shell|spectral) '
                           '[default : dot]'
                           )

        parser.add_option('--na', '--no-arrows',
                      action='store_false', dest='Arrows', default=True,
                      help='do not output any arrows [Graphml]')
        parser.add_option('--nc', '--no-colors',
                      action='store_false', dest='Colors', default=True,
                      help='do not output any colors [Graphml]')
        parser.add_option('--nn', '--no-nodes',
                      action='store_false', dest='NodeLabels', default=True,
                      help='do not output any node labels [Graphml]')
        parser.add_option('--nu', '--no-uml',
                      action='store_false', dest='NodeUml', default=True,
                      help='do not output any node methods/attributes in UML [Graphml]')
        parser.add_option('--la', '--lump-attributes',
                      action='store_true', dest='LumpAttributes', default=False,
                      help='lump class attributes/methods together with the node label [Graphml]')
        parser.add_option('--sc', '--separator-char',
                      action='store', dest='SepChar', default='_', metavar='SEPCHAR',
                      help='default separator char when lumping attributes/methods [default : "_"]')
        parser.add_option('--ne', '--no-edges',
                      action='store_false', dest='EdgeLabels', default=True,
                      help='do not output any edge labels [Graphml]')
        parser.add_option('--ae', '--auto-edges',
                      action='store_true', dest='EdgeLabelsAutoComplete', default=False,
                      help='auto-complete edge labels')


        parser.add_option('--cn', '--color-nodes',
                      action='store', dest='DefaultNodeColor', default='#CCCCFF', metavar='COLOR',
                      help='default node color [default : "#CCCCFF"]')
        parser.add_option('--cnt', '--color-nodes-text',
                      action='store', dest='DefaultNodeTextColor', default='#000000', metavar='COLOR',
                      help='default node text color for labels [default : "#000000"]')
        parser.add_option('--ce', '--color-edges',
                      action='store', dest='DefaultEdgeColor', default='#000000', metavar='COLOR',
                      help='default edge color [default : "#000000"]')
        parser.add_option('--cet', '--color-edges-text',
                      action='store', dest='DefaultEdgeTextColor', default='#000000', metavar='COLOR',
                      help='default edge text color for labels [default : "#000000"]')
        parser.add_option('--ah', '--arrowhead',
                      action='store', dest='DefaultArrowHead', default='none', metavar='TYPE',
                      help='sets the default appearance of arrow heads for edges (normal|diamond|dot|...) [default : %default]')
        parser.add_option('--at', '--arrowtail',
                      action='store', dest='DefaultArrowTail', default='none', metavar='TYPE',
                      help='sets the default appearance of arrow tails for edges (normal|diamond|dot|...) [default : %default]')


	try:
		#opts, args = getopt.getopt(argv, 'f:g:d:r:t:F:c:C:')
		options, args = parser.parse_args()
	except getopt.GetoptError:
		print_syntax()
		sys.exit(1)
	opt_root_ip = options.root_ip
	opt_dot = options.dot
	opt_graphml = options.graphml
	opt_depth = options.depth
	max_depth = options.depth
	opt_title = options.title
	opt_conf = options.conf
	opt_catalog = options.catalog

	if not (len(opt_root_ip) >= 0 and (opt_dot or opt_graphml)):
		print_syntax()
		print('Invalid arguments.')
		return

	print('     Config file: %s' % opt_conf)
	print('       Root node: %s' % ', '.join(opt_root_ip))
	if opt_dot: print('     Output file: %s' % opt_dot)
	if opt_graphml: print('     Output file: %s' % opt_graphml)
	print('     Crawl depth: %s' % opt_depth)
	print('   Diagram title: %s' % opt_title)
	print('Out Catalog file: %s' % opt_catalog)

	print('\n\n')

	# load the config
	if (graph.load_config(opt_conf) == 0):
		return
	graph.set_max_depth(opt_depth)

	# start
	graph.crawl(opt_root_ip)
		
	# outputs
	graph.output_stdout()

	if (opt_dot != None):
		graph.output_dot(opt_dot, opt_title)

	if (opt_graphml != None):
		graph.output_graphml(opt_graphml, opt_title, options)

	if (opt_catalog != None):
		graph.output_catalog(opt_catalog)


def tracemac(argv):
	trace = mnetsuite.mnet_tracemac()

	opt_root_ip = []
	opt_conf = './mnet.conf'
	opt_mac = None

	try:
		opts, args = getopt.getopt(argv, 'r:c:m:')
	except getopt.GetoptError:
		print_syntax()
		return
	for opt, arg in opts:
		if (opt == '-r'):
			opt_root_ip.append(arg)
		if (opt == '-c'):
			opt_conf = arg
		if (opt == '-m'):
			opt_mac = arg

	if ((len(opt_root_ip) == 0) or (opt_mac == None)):
		print_syntax()
		print('Invalid arguments.')
		return

	print('     Config file: %s' % opt_conf)
	print('       Root node: %s' % ', '.join(opt_root_ip))
	print('     MAC address: %s' % opt_mac)

	print('\n\n')

	mac = trace.parse_mac(opt_mac)
	if (mac == None):
		print('MAC address is invalid.')
		return

	# load config
	trace.load_config(opt_conf)

	# start
	print('Start trace.')
	print('------------')

	for ip in opt_root_ip:
	    while (ip != None):
		ip = trace.trace(ip, mac)
		print('------------')

	print('Trace complete.\n')


def generate_config():
	conf = mnetsuite.config.mnet_config()
	print('%s' % conf.generate_new())


if __name__ == "__main__":
	main(sys.argv[1:])

