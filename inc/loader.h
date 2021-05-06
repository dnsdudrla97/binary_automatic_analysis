#ifndef LOADER_H
#define LOADER_H

#include <stdint.h>
#include <string>
#include <vector>

/*
* 가장 최상위 클래스이며, 전체 바이너리의 추상화된 계층을 나타낸다.
*/
class Binary; 

/*
* 섹션을 처리하기 위한 벡터 객체
*/
class Section;
/*
* 심벌을 처리하기 위한 벡터 객체
* 섹션과 심볼은 각 바이너리에 포함된 정보를 나타낸다.
*/
class Symbol;

/**
* 1 Symbol
* - 심벌을 처리하기 위한 벡터 객체
* - 해당 부분에서 사용할 로더 인터페이스는 오직 함수 심벌에 대해서만 표현하도록 
* - 함수 심절 정보를 표현하고자 한다면 함수 수준의 바이너리 분석 도구를 만들기에 수월
* - 심벌에 명세된 해당 함수의 기호명, 시작 주소도 함께 클래스에 저장된다.
*/
class Symbol {
public:
  enum SymbolType {
    SYM_TYPE_UKN  = 0,
    SYM_TYPE_FUNC = 1
  };

  Symbol() : type(SYM_TYPE_UKN), name(), addr(0) {}

  SymbolType  type;
  std::string name;
  uint64_t    addr;
};
/**
* 2 Section
* - 섹션을 처리하기 위한 벡터 객체
* - 섹션의 이름, 타입, 시작 주소(.vma), 크기(byte), 바이트 정보
* - Section 객체를 포함한 Bianry 객체를 거꾸로 찾아주는 포인터
*/
class Section {
public:
  enum SectionType {
    SEC_TYPE_NONE = 0,
    SEC_TYPE_CODE = 1,
    SEC_TYPE_DATA = 2
  };

  Section() : binary(NULL), type(SEC_TYPE_NONE), vma(0), size(0), bytes(NULL) {}

  bool contains (uint64_t addr) { return (addr >= vma) && (addr-vma < size); }

  Binary       *binary;
  std::string   name;
  SectionType   type;
  uint64_t      vma;
  uint64_t      size;
  uint8_t       *bytes;
};
/**
* 3 Binary class (top-level)
* - 전체 바이너리의 추상화된 게층을 나타낸다.
* - 바이너리 파일명, 타입, 아키텍처, 비트 크기, 엔트리 포인트 주소, 섹션, 심벌정보
*/
class Binary {
public:
  enum BinaryType {
    BIN_TYPE_AUTO = 0,
    BIN_TYPE_ELF  = 1,
    BIN_TYPE_PE   = 2
  };
  enum BinaryArch {
    ARCH_NONE = 0,
    ARCH_X86  = 1
  };

  Binary() : type(BIN_TYPE_AUTO), arch(ARCH_NONE), bits(0), entry(0) {}

  Section *get_text_section() { for(auto &s : sections) if(s.name == ".text") return &s; return NULL; }

  std::string          filename;
  BinaryType           type;
  std::string          type_str;
  BinaryArch           arch;
  std::string          arch_str;
  unsigned             bits;
  uint64_t             entry;
  std::vector<Section> sections;
  std::vector<Symbol>  symbols;
};
/**
* 4
* - 로드할 바이너리의 해당 정보를 바탕으로 요청된 바이너리를 로드해 매개 변수 bin에 연결
* @arg : (string) &fname -> 로드할 바이너리 파일 이름
* @arg : (Bianry) *bin -> 로드된 바이너리를 가리킬 바이너리 객체의 포인터(bin)
* @arg : (Binary:BinaryType) type -> 해당 바이너리의 타입 정보를 입력
* @return : 로드 과정 ? 0 : 0 이하의 값
*/
int  load_binary (std::string &fname, Binary *bin, Binary::BinaryType type);
/**
* 5
* 앞서 로드된 바이너리 객체를 확인하고 이를 해제하는 역화을 수행한다.
*/
void unload_binary (Binary *bin);

#endif /* LOADER_H */

