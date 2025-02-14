# All configuration must occur within this file.
# All other files may be overwritten during upgrade 
module FileExtraction;

# Configure where extracted files will be stored
redef path = "/file-extraction/";

# Configure 'plugins' that can be loaded
# these are shortcut modules to specify common 
# file extraction policies. Example:
@load ./plugins/extract-pe.zeek
# @load ./plugins/extract-common-exploit-types
