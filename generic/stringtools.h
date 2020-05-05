#pragma once

#include <string>
#include <vector>

class Joiner {                                                                  
   public:                                                                      
    Joiner(const std::string &sep) : separator_(sep) {}                         

    /*MapJoiner withKeyValueSeparator(const std::string &kvSeparator) {           
        return MapJoiner(*this, kvSeparator);                                   
    }*/                                                                          
                                                                                
    template <typename T>                                                       
    std::string join(const T &collection) const {                               
        std::string ret;                                                        
        for (const auto &it : collection) {                                     
            ret += it + separator_;                                             
        }                                                                       
                                                                                
        if (!ret.empty())                                                       
            ret.erase(ret.size() - separator_.size(),                           
                      separator_.size());                                       
        return ret;                                                             
    }                                                                           
                                                                                
    static Joiner on(const std::string &separator) { return Joiner(separator); }
                                                                                
   private:                                                                     
    std::string separator_;                                                     
};

std::vector<std::string> split(const std::string& str, const std::string& delim,
                               char escape = 0);
