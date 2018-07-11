#ifndef _VECTOR_H_
#define _VECTOR_H_

#include <memory.h>

#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

template <class Type>
class Vector
{
public:
    Vector()
    {
        _buf = new Type[16];
        _capacity = 16;
        _size = 0;
    }
    
    Vector(size_t n)
    {
        _buf = new Type[n];
        verify(_buf);
        _capacity = n;
        _size = 0;
    }
    
    const Type * data()
    {
        return _buf;
    }
    
    size_t capacity()const
    {
        return _capacity;
    }
    
    size_t size()const
    {
        return _size;
    }
    
    void clear()
    {
        _size = 0;
    }
    
    void push_back(const Type & x)
    {
        if(_size == _capacity)
        {
            Type * old_buf = _buf;
            
            _capacity *= 2;
            _buf = new Type[_capacity];
            verify(_buf);
            
            for(size_t i = 0; i < _size; i++)
            {
                _buf[i] = old_buf[i];
            }
            
            delete old_buf;
        }
        
        _buf[_size] = x;
        _size++;
    }
    
    void push_back(const Type arr[], size_t n)
    {
        if(_size + n > _capacity)
        {
            Type * old_buf = _buf;
            
            while(_capacity < _size + n)
            {
                _capacity *= 2;
            }
            
            _buf = new Type[_capacity];
            verify(_buf);
            
            for(size_t i = 0; i < _size; i++)
            {
                _buf[i] = old_buf[i];
            }
            
            delete old_buf;
        }
        
        for(size_t i = 0; i < n; i++, _size++)
        {
            _buf[_size] = arr[i];
        }
    }

protected:
    Type * _buf;
    size_t _capacity;
    size_t _size;
};

#endif
