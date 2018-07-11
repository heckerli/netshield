#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <cassert>

#include "NetShield.h"
#include "Util.h"
#include "BufferEventHandler.h"

class Buffer
{
public:
    Buffer();
    virtual ~Buffer();
    
    BufferEventHandler * setEventHandler(BufferEventHandler * eventHandler);
    
    inline INT32_T newData(UINT8_T * data, UINT32_T dataLength)
    {
        assert(this->dataBegin == NULL);
        
        if(bSkipAll == true)
        {
            return 0;
        }
        
        this->dataBegin = data;
        this->dataEnd = data + dataLength;
        this->dataPtr = data;
        
        this->recallPoint = NULL;
    
    	return 0;
    }
    
    inline UINT32_T getLength()
    {
        if(dataPtr >= dataEnd)
        {
            return 0;
        }
        else
        {
            return dataEnd - dataPtr;
        }
    }
    
    inline UINT8_T readUInt8()
    {
        while(dataPtr >= dataEnd)
        {
            dataBegin = NULL;
            dataEnd = NULL;
            dataPtr = NULL;
            
            if(eventHandler != NULL)
            {
                eventHandler->onBufferEmpty(this);
            }
        }
        
        UINT8_T result = *dataPtr++;
        byteCount++;
        
        return result;
    }
    
    inline void readUInt16(UINT16_T * result)
    {
        UINT8_T * p = (UINT8_T *)result;
        
        if(dataEnd - dataPtr >= 2)
        {
            *result = *((UINT16_T *)dataPtr);
            
            dataPtr += 2;
            byteCount += 2;
        }
        else
        {
            *p = readUInt8();
            *(p + 1) = readUInt8();
        }
    }
    
    inline void readUInt16Ntohs(UINT16_T * result)
    {
        UINT8_T * p = (UINT8_T *)result;
        
        if(dataEnd - dataPtr >= 2)
        {
            *(p + 1) = *dataPtr++;
            *p = *dataPtr++;
            byteCount += 2;
        }
        else
        {
            *(p + 1) = readUInt8();
            *p = readUInt8();
        }
    }
    
    inline void readUInt32(UINT32_T * result)
    {
        UINT8_T * p = (UINT8_T *)result;
        
        if(dataEnd - dataPtr >= 4)
        {
            *result = *((UINT32_T *)dataPtr);
            
            dataPtr += 4;
            byteCount += 4;
        }
        else
        {
            *p = readUInt8();
            *(p + 1) = readUInt8();
            *(p + 2) = readUInt8();
            *(p + 3) = readUInt8();
        }
    }
    
    inline void skip(UINT32_T byteNum)
    {
        register UINT32_T validLength = dataEnd - dataPtr;
        if(validLength >= byteNum)
        {
            dataPtr += byteNum;
            byteCount += byteNum;
            return;
        }
        
        while(byteNum > 0)
        {
            validLength = dataEnd - dataPtr;
            if(validLength >= byteNum)
            {
                dataPtr += byteNum;
                byteCount += byteNum;
                
                return;
            }
            else
            {
                byteCount += validLength;
                byteNum -= validLength;
                
                dataBegin = NULL;
                dataEnd = NULL;
                dataPtr = NULL;
                
                if(eventHandler != NULL)
                {
                    eventHandler->onBufferEmpty(this);
                }
            }
        }
        
        return;
    }

    inline INT32_T skipFlow()
    {
        byteCount += dataEnd - dataPtr;
        
        dataBegin = NULL;
        dataEnd = NULL;
        dataPtr = NULL;
        
        bSkipAll = true;
        
        return 0;
    }

    inline STRING_T readLine(LineBreakStyle lineBreakStyle)
    {
        STRING_T line;
        
        // CR or LF should be in the line returned.
        if(lineBreakStyle == CR_AND_LF)
        {
            UINT8_T ch = readUInt8();
            UINT8_T ch1 = readUInt8();
            line += ch;
            line += ch1;
            while(ch != '\r' || ch1 != '\n')
            {
                ch = ch1;
                ch1 = readUInt8();
                line += ch1;
            }
        }
        else if(lineBreakStyle == CRLF_OR_LF)
        {
            UINT8_T ch = readUInt8();
            line += ch;
            while(ch != '\n')
            {
                if(ch != '\r')
                {
                    ch = readUInt8();
                    line += ch;
                }
                else
                {
                    UINT8_T ch1 = readUInt8();
                    line += ch1;
                    if(ch1 != '\n')
                    {
                        ch = ch1;
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
        
        return line;
    }
    
    inline INT32_T readArray(UINT8_T * array, UINT32_T arrayLength)
    {
        if(dataPtr + arrayLength <= dataEnd)
        {
            memcpy(array, dataPtr, arrayLength);
            dataPtr += arrayLength;
            byteCount += arrayLength;
        }
        else
        {
            for(UINT32_T i = 0; i < arrayLength; i++)
            {
                array[i] = readUInt8();
            }
        }
        
        return arrayLength;
    }
    
    inline INT32_T readAll(UINT8_T ** begin, UINT32_T * length)
    {
        while(dataPtr >= dataEnd)
        {
            dataBegin = NULL;
            dataEnd = NULL;
            dataPtr = NULL;
            
            if(eventHandler != NULL)
            {
                eventHandler->onBufferEmpty(this);
            }
        }
        
        *begin = dataPtr;
        *length = dataEnd - dataPtr;
        
        dataBegin = NULL;
        dataEnd = NULL;
        dataPtr = NULL;
        
        return 0;
    }
    
    inline INT32_T pushBack(UINT8_T ch)
    {
        if(dataPtr > dataBegin)
        {
            dataPtr--;
            *dataPtr = ch;
        }
        else
        {
            UINT8_T * oldDataBegin = dataBegin;
            
            UINT32_T dataLength = dataEnd - dataPtr + 1;
            dataBegin = new UINT8_T[dataLength];
            verify(dataBegin);
            memcpy((dataBegin + 1), dataPtr, dataLength - 1);
            *dataBegin = ch;
            dataEnd = dataBegin + dataLength;
            dataPtr = dataBegin;
            
            recallPoint = NULL;
        }
        
        byteCount--;
        return 0;
    }
    
    inline INT32_T getByteCount()
    {
        return byteCount;
    }
    
    inline UINT8_T * setRecallPoint()
    {
        UINT8_T * oldRecallPoint = recallPoint;
        recallPoint = dataPtr;
        
        return oldRecallPoint;
    }
    
    inline UINT8_T * getRecallPoint()const
    {
        return recallPoint;
    }
    
    inline UINT8_T * getCurrentDataPtr()
    {
        while(dataPtr >= dataEnd)
        {
            dataBegin = NULL;
            dataEnd = NULL;
            dataPtr = NULL;
            
            if(eventHandler != NULL)
            {
                eventHandler->onBufferEmpty(this);
            }
        }
        
        return dataPtr;
    }
    
    INT32_T reset()
    {
        bSkipAll = false;

		return 0;
    }
    
protected:
    BufferEventHandler * eventHandler;
    INT32_T byteCount;
    
    UINT8_T * dataBegin;
    UINT8_T * dataEnd;
    UINT8_T * dataPtr;
    
    UINT8_T * recallPoint;
    
    BOOL_T bSkipAll;
};

#endif
