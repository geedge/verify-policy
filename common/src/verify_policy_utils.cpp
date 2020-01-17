#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

char* rt_strdup(const char* s)
{
	char*d=NULL;
	if(s==NULL)
	{
		return NULL;
	}

	d=(char*)malloc(strlen(s)+1);
	memcpy(d,s,strlen(s)+1);
	return d;
}

