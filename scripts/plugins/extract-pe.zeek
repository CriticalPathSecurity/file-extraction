# Change to minimum file size to assist in muting broken flow extractions
# Critical Path Security / Patrick Kelley

@load ../__load__

module FileExtraction;

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5
	{
	if ( meta$mime_type == "application/x-dosexec" && f$seen_bytes > 10 )
		break;
	}
