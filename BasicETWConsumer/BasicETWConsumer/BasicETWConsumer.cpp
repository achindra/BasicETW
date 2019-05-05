// BasicETWConsumer.cpp : Defines the entry point for the console application.
//

#define INITGUID

#include "stdafx.h"
#include <Windows.h>
#include <stdlib.h>
#include <initguid.h>

#include <tdh.h>
#include <evntrace.h>

#pragma comment(lib,"tdh.lib")

#define LOG_FILE_PATH L"C:\\Users\\AchinBha\\SkyDrive\\Documents\\Win8\\11_Day5(Fri)-ClassExercise\\ClassExamples\\OEM\\Phil\\win8printtest_XPS-PCL6.etl"

void WINAPI ProcessEvent(PEVENT_RECORD pEvent);
void PrintMapString(PEVENT_MAP_INFO pMapInfo, PBYTE pData);
DWORD GetMapInfo(PEVENT_RECORD pEvent, LPWSTR pMapName, DWORD DecodingSource, PEVENT_MAP_INFO & pMapInfo);
DWORD FormatAndPrintData(PEVENT_RECORD pEvent, USHORT InType, USHORT OutType, PBYTE pData, DWORD DataSize, PEVENT_MAP_INFO pMapInfo); 


TRACEHANDLE g_hTrace = 0;  

int _tmain(int argc, _TCHAR* argv[])
{
	TDHSTATUS  Status = ERROR_SUCCESS;
	PEVENT_TRACE_LOGFILE pLogFile = NULL;
	
	pLogFile = (PEVENT_TRACE_LOGFILE) malloc(sizeof(EVENT_TRACE_LOGFILE));
	if(NULL == pLogFile)
	{
		printf("Error No Mem! \n");
		return ERROR_SUCCESS;
	}

	ZeroMemory(pLogFile, sizeof(EVENT_TRACE_LOGFILE));

	pLogFile->LogFileName = LOG_FILE_PATH;
	pLogFile->ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;

	//pLogFile->LoggerName = L"TestTrace";
	//pLogFile->ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME;// EVENT_TRACE_REAL_TIME_MODE;

	pLogFile->EventCallback = (PEVENT_CALLBACK) (ProcessEvent);

	g_hTrace = OpenTrace(pLogFile);

	if(INVALID_PROCESSTRACE_HANDLE == g_hTrace)
	{
		printf("OpenTrace failed with error %x \n", GetLastError());
		goto CleanUp;
	}

	Status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if(ERROR_SUCCESS != Status && ERROR_CANCELLED !=Status)
	{
		printf("ProcessTrace failed with error %x \n", Status);
		goto CleanUp;
	}


CleanUp:

	if(INVALID_PROCESSTRACE_HANDLE!=g_hTrace)
		Status = CloseTrace(g_hTrace);

	g_hTrace = 0;
	free(pLogFile);

	return Status;
}


void WINAPI ProcessEvent(PEVENT_RECORD pEvent)
{
	//
	// Vista+: Consume data using TDH, 
	//   that were published using a manifest, MOF, or TMF files
	//

	TDHSTATUS Status = ERROR_SUCCESS;
	const DWORD BUF_SIZE = 1024;
	DWORD BufferSize = 0;
	PBYTE pData = NULL;
	PEVENT_MAP_INFO pMapInfo = NULL;
    PROPERTY_DATA_DESCRIPTOR DataDescriptors[2];
    ULONG DescriptorsCount = 0;
    DWORD PropertySize = 0;
	PTRACE_EVENT_INFO pTraceEventInfo = NULL;
	
	PEVENT_PROPERTY_INFO pEventPropertyInfo = NULL;
	BYTE pPropertyBuffer[BUF_SIZE];
	PROPERTY_DATA_DESCRIPTOR propertyDataDesc;
	LPWSTR pszPropertyName = NULL;
	PTRACE_EVENT_INFO pInfo = NULL;

	DWORD index = 0;

	DWORD dwBufferSize = sizeof(TRACE_EVENT_INFO)+BUF_SIZE;

	pTraceEventInfo = (PTRACE_EVENT_INFO)malloc(dwBufferSize);
	if(NULL==pTraceEventInfo)
	{
		printf("Error No Mem! \n");
		return;
	}

	ZeroMemory(pTraceEventInfo,dwBufferSize);

	Status = TdhGetEventInformation(pEvent, 0, NULL, pTraceEventInfo, &dwBufferSize);

	if(ERROR_SUCCESS != Status)
	{
		printf("Error in TdhGetEventInformation: %x \n", Status);
		goto CleanUp;
	}

	//
	//Skip Header Event
	//  Similarly filter by GUID
	//
	if(IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
		pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO)
	{
		;//skip
	}
	else
	{
		for(index=0; index<pTraceEventInfo->TopLevelPropertyCount; index)
		{
			pEventPropertyInfo = &pTraceEventInfo->EventPropertyInfoArray[index];
			printf("----Event Property Info----\n");
			pszPropertyName = (LPWSTR)((PBYTE)pTraceEventInfo+pEventPropertyInfo->NameOffset);
			printf("PropertyName: %ws\n", pszPropertyName);
			printf("Length: %d\n",pEventPropertyInfo->length);
			printf("InType: %u\n", pEventPropertyInfo->nonStructType.InType);

			ZeroMemory(pPropertyBuffer,BUF_SIZE);
			propertyDataDesc.PropertyName = (ULONGLONG)pszPropertyName;
			propertyDataDesc.ArrayIndex = ULONG_MAX;

			Status = TdhGetProperty(pEvent,0,NULL,1, &propertyDataDesc,BUF_SIZE,pPropertyBuffer);
			if(ERROR_SUCCESS != Status)
			{
				printf("TdhGetProperty failed: %x\n", Status);
				goto CleanUp;
			}

			Status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);

			if (ERROR_INSUFFICIENT_BUFFER == Status)
			{
				pInfo = (TRACE_EVENT_INFO*) malloc(BufferSize);
				if (pInfo == NULL)
				{
					wprintf(L"Failed to allocate memory for event info (size=%lu).\n", BufferSize);
					Status = ERROR_OUTOFMEMORY;
					goto CleanUp
						;
				}

				// Retrieve the event metadata.

				Status = TdhGetEventInformation(pEvent, 0, NULL, pInfo, &BufferSize);
			}

			if (ERROR_SUCCESS != Status)
			{
				printf("TdhGetEventInformation failed with 0x%x.\n", Status);
				goto CleanUp;
			}

			ZeroMemory(&DataDescriptors, sizeof(DataDescriptors));
			if (pStructureName)
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)pStructureName;
                DataDescriptors[0].ArrayIndex = StructIndex;
                DataDescriptors[1].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[1].ArrayIndex = k;
                DescriptorsCount = 2;
            }
            else
            {
                DataDescriptors[0].PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
                DataDescriptors[0].ArrayIndex = k;
                DescriptorsCount = 1;
            }

			Status = TdhGetPropertySize(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], &PropertySize);

                if (ERROR_SUCCESS != Status)
                {
                    wprintf(L"TdhGetPropertySize failed with %lu\n", Status);
                    goto CleanUp;
                }

			Status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);
			if (ERROR_SUCCESS != Status)
            {
                printf("TdhGetPropertySize failed with %lu\n", Status);
                goto CleanUp;
            }

			pData = (PBYTE)malloc(PropertySize);

            if (NULL == pData)
            {
                wprintf(L"Failed to allocate memory for property data\n");
                Status = ERROR_OUTOFMEMORY;
                goto CleanUp;
            }

            Status = TdhGetProperty(pEvent, 0, NULL, DescriptorsCount, &DataDescriptors[0], PropertySize, pData);


            // Get the name/value mapping if the property specifies a value map.

            Status = GetMapInfo(pEvent, 
                (PWCHAR)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[index].nonStructType.MapNameOffset),
                pInfo->DecodingSource,
                pMapInfo);

            if (ERROR_SUCCESS != Status)
            {
                wprintf(L"GetMapInfo failed\n");
                goto CleanUp;
            }

			Status = FormatAndPrintData(pEvent, 
                    pInfo->EventPropertyInfoArray[index].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[index].nonStructType.OutType,
                    pData, 
                    PropertySize,
                    pMapInfo 
                    );

                if (ERROR_SUCCESS != Status)
                {
                    printf("GetMapInfo failed: %x\n", Status);
                    goto CleanUp;
                }
		}

		//if(EVENT_HEADER_FLAG_STRING_ONLY || pEvent->EventHeader.Flags)
		//	printf(" > %s \n", pEvent->UserData);
	}

CleanUp:
	if(pData)
		free(pData);
	if(pInfo)
		free(pInfo);
	if(pTraceEventInfo)
		free(pTraceEventInfo);
	return;
}
