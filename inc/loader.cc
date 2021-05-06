#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <vector>
#include <bfd.h>
#include "loader.h"

/**
 * 주어진 파일이름 (fname) 에 기반하여 해당 바이너리의 속성을 결정하고자 (libbfd) -> 바이너리 속성 결정
 * libbfd -> 바이너리 open -> 바이너리 연결용 핸들(반환)
*/
static bfd* open_bfd(std::string &fname)
{
  static int bfd_inited = 0;

  bfd *bfd_h;
  /*
  * libbfd를 사용하려면 먼저 bfd_init 선행
  * libbfd의 내부 상태를 초기화해줘야 한다. (내부 자료 구조 준비 태세로 갖추는 마법 같은 동작)
  * open_bfd 함수는 정적 변수 를 사용하여 진행 과정을 추적 초기화 동작이 이미 수행됐는지 확인한다.
  */
  if(!bfd_inited) {
    bfd_init();
    bfd_inited = 1;
  }
  /*
  * bfd_openr 함수 호출시 파일명 확인 및 해당 바이너리를 여는 작업을 수행한다.
  * 두 번째 매개변수: 대상 바이너리가 어떤 형식인지(바이너리 타입) -> NULL: 자동으로 판별
  * 반환 값: bfd 타입의 파일 핸들 포인터를 반환(libbfd 최상위 자료 구조), NULL(오류)
  */
  bfd_h = bfd_openr(fname.c_str(), NULL);
  if(!bfd_h) {
    fprintf(stderr, "failed to open binary '%s' (%s)\n",
            /*bfd_get_error
            * 반환 값: bgf_error_type 객체
            * bfd_no_memory, bfd_error_invalid_target ..., 다양한 식별자와 비교하여 해당 오류를 어떻게 잡을 지 판단
            */
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }
  /*
  * 반환된 bfd_openr 핸들을 bfd_check_format 함수를 사용해 바이너리의 포맷을 확인한다.
  * bfd 핸들 bfd_format 값을 지정하는데,
  * 해당 값은 bfd_object, archive, core등으로 설정된다.
  * bfd_object->객체, 즉 실행 가능한 바이너리 파일이나 재배치 가능한 목적 파일, 공유라이브러리에 속하는지 확인  
  */
  if(!bfd_check_format(bfd_h, bfd_object)) {
    fprintf(stderr, "file '%s' does not look like an executable (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  /*
  * 일부 버전의 bfd_check_format 함수는 형식을 감지하기 전에 먼저 '잘못된 형식 오류'로 초기 설정한 다음,
  * 형식이 감지되면 설정을 해제하는 다소 비관적인 전략을 취한다.
  * 이러한 설정으로 발생하는 혹시 모를 오류를 방지하고자 강제로 해당 설정을 해제하는 코드를 넣었다.
  * */
  bfd_set_error(bfd_error_no_error);

  /*
  * 바이너리에 알려진 특징이 있는지 -> 어떤 종류에 속하는지 (ELF, PE...)
  * bfd_target_msods_flavour, _coff_, _elf_, 
  * 알수 없는 경우 _unknown_
  */
  if(bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour) {
    fprintf(stderr, "unrecognized format for binary '%s' (%s)\n",
            fname.c_str(), bfd_errmsg(bfd_get_error()));
    return NULL;
  }

  return bfd_h;
}

/* 심벌 정보 불러오기 (정적) */
static int
load_symbols_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
   /*구조체 bfd_symbol을 축약, 심벌들의 집합인 테이블은 이중 포인터 타입으로 지정( 심벌 포인터의 배열)
   * asymbol 포인터 배열 안에 값을 채워 넣고 유의미한 정보를 Binary 객체에 복사하는 것
   */
  asymbol **bfd_symtab;
  Symbol *sym;

  bfd_symtab = NULL;
  /*
  * 심벌 포인터를 로드할려면 그에 따른 공간이 있어야 하며 밑의 함수는 필요한 용량을 바이트 단위로 알려줌
  */
  n = bfd_get_symtab_upper_bound(bfd_h);
  if(n < 0) {
    fprintf(stderr, "failed to read symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_symtab = (asymbol**)malloc(n);
    if(!bfd_symtab) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    /*
    * - 심벌 테이블 조회할 준비 완료 - 
    * 입력 값으로는 bfd 핸들과 채워 넣을 기호 테이블(symbol**)을 지정한다.
    * libbfd는 심벌 테이블을 적절하게 채우고 테이블에 배치된 심벌의 수가 몇 개인지를 반환
    */
    nsyms = bfd_canonicalize_symtab(bfd_h, bfd_symtab);
    if(nsyms < 0) {
      fprintf(stderr, "failed to read symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      /* BSF_FUNCTION 플래그 설정 여부 판별*/
      if(bfd_symtab[i]->flags & BSF_FUNCTION) {
        /*함수 심벌에 해당하는 경우 바이너리 객체 Bianry에서 로드된 심벌들을 저장하고 있는 벡터에 항목을 새로 추가
        * 해당 심벌 객체인 Symbol(로더가 심볼을 저장할 때 사용하고자 자체적으로 정의한 심벌 클래스)을 담을 공간을 마련
        */
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_symtab[i]->name);
        // 함수의 시작 주소는 함수 심벌의 값과 같다.
        sym->addr = bfd_asymbol_value(bfd_symtab[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_symtab) free(bfd_symtab);

  return ret;
}


static int
load_dynsym_bfd(bfd *bfd_h, Binary *bin)
{
  int ret;
  long n, nsyms, i;
  asymbol **bfd_dynsym;
  Symbol *sym;

  bfd_dynsym = NULL;

  n = bfd_get_dynamic_symtab_upper_bound(bfd_h);
  if(n < 0) {
    fprintf(stderr, "failed to read dynamic symtab (%s)\n",
            bfd_errmsg(bfd_get_error()));
    goto fail;
  } else if(n) {
    bfd_dynsym = (asymbol**)malloc(n);
    if(!bfd_dynsym) {
      fprintf(stderr, "out of memory\n");
      goto fail;
    }
    nsyms = bfd_canonicalize_dynamic_symtab(bfd_h, bfd_dynsym);
    if(nsyms < 0) {
      fprintf(stderr, "failed to read dynamic symtab (%s)\n",
              bfd_errmsg(bfd_get_error()));
      goto fail;
    }
    for(i = 0; i < nsyms; i++) {
      if(bfd_dynsym[i]->flags & BSF_FUNCTION) {
        bin->symbols.push_back(Symbol());
        sym = &bin->symbols.back();
        sym->type = Symbol::SYM_TYPE_FUNC;
        sym->name = std::string(bfd_dynsym[i]->name);
        sym->addr = bfd_asymbol_value(bfd_dynsym[i]);
      }
    }
  }

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_dynsym) free(bfd_dynsym);

  return ret;
}


static int
load_sections_bfd(bfd *bfd_h, Binary *bin)
{
  int bfd_flags;
  uint64_t vma, size;
  const char *secname;
  asection* bfd_sec;
  Section *sec;
  Section::SectionType sectype;

  for(bfd_sec = bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
    bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

    sectype = Section::SEC_TYPE_NONE;
    if(bfd_flags & SEC_CODE) {
      sectype = Section::SEC_TYPE_CODE;
    } else if(bfd_flags & SEC_DATA) {
      sectype = Section::SEC_TYPE_DATA;
    } else {
      continue;
    }

    vma     = bfd_section_vma(bfd_h, bfd_sec);
    size    = bfd_section_size(bfd_h, bfd_sec);
    secname = bfd_section_name(bfd_h, bfd_sec);
    if(!secname) secname = "<unnamed>";

    bin->sections.push_back(Section());
    sec = &bin->sections.back();

    sec->binary = bin;
    sec->name   = std::string(secname);
    sec->type   = sectype;
    sec->vma    = vma;
    sec->size   = size;
    sec->bytes  = (uint8_t*)malloc(size);
    if(!sec->bytes) {
      fprintf(stderr, "out of memory\n");
      return -1;
    }

    if(!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
      fprintf(stderr, "failed to read section '%s' (%s)\n",
              secname, bfd_errmsg(bfd_get_error()));
      return -1;
    }
  }

  return 0;
}


static int
load_binary_bfd(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  int ret;
  bfd *bfd_h;
  const bfd_arch_info_type *bfd_info;

  bfd_h = NULL;
  /* bfd 핸들 */
  bfd_h = open_bfd(fname);
  if(!bfd_h) {
    goto fail;
  }
  bin->filename = std::string(fname);
  /* 바이너리 파일 이름을 복사하고 libbfd를 사용하여 엔트리 포인트 주소를 찾아 복사해온다.
  *  bfd 객체의 start_address 필드 값을 확인할 수 있다.
  * 시작 주소-> bfd_vma(64비트 부호없는 정수 형태)
  */
  bin->entry    = bfd_get_start_address(bfd_h);
  /*
  * 아키텍처 여부를 확인할려면 bfd_target 구조체 확인 (bfd 핸들의 xvec 필드를 참조한다.)
  * bfd_h->xvec 코드로 작성하면 bfd_target 구조체 포인터를 얻을 수 있다.
  * bfd_target 구조체는 해당 바이너리의 타입에 대응하는 문자열로 된 정보도 포함한다.
  */
  bin->type_str = std::string(bfd_h->xvec->name);
  switch(bfd_h->xvec->flavour) {
  case bfd_target_elf_flavour:
    bin->type = Binary::BIN_TYPE_ELF;
    break;
  case bfd_target_coff_flavour:
    bin->type = Binary::BIN_TYPE_PE;
    break;
  case bfd_target_unknown_flavour:
  default:
    fprintf(stderr, "unsupported binary type (%s)\n", bfd_h->xvec->name);
    goto fail;
  }
  /* 어떤 아키텍처 환경인지 확인
  * 바이너리가 컴파일된 아키텍처 환경의 정보를 알려주는 포인터를 반환한다.
  * 자료구조 bfd_arch_info_type
  */
  bfd_info = bfd_get_arch_info(bfd_h);
  /* 문자열 형태로 복사하여 값을 binary 객체에 저장한다.*/
  bin->arch_str = std::string(bfd_info->printable_name);
  switch(bfd_info->mach) {
  case bfd_mach_i386_i386:
    bin->arch = Binary::ARCH_X86; 
    bin->bits = 32;
    break;
  case bfd_mach_x86_64:
    bin->arch = Binary::ARCH_X86;
    bin->bits = 64;
    break;
  default:
    fprintf(stderr, "unsupported architecture (%s)\n",
            bfd_info->printable_name);
    goto fail;
  }

  /* Symbol handling is best-effort only (they may not even be present) */
  load_symbols_bfd(bfd_h, bin); /* 정적 심볼 로드*/
  load_dynsym_bfd(bfd_h, bin);  /* 동적 심볼 로드 */
  /* tprtus wjdqh fhem */
  if(load_sections_bfd(bfd_h, bin) < 0) goto fail;

  ret = 0;
  goto cleanup;

fail:
  ret = -1;

cleanup:
  if(bfd_h) bfd_close(bfd_h);

  return ret;
}


int
load_binary(std::string &fname, Binary *bin, Binary::BinaryType type)
{
  return load_binary_bfd(fname, bin, type);
}


/*
* 생성했던 바이너리 객체의 로드를 해제하려면 로더 내부에서 동적으로 할당된
* 모든 컴포넌트들을 삭제해야 한다.
* 각 섹션 객체의 멤버 변수인 바이트만 malloc을 사용해 동적으로 할당된 항목이다.
* 모든 섹션 객체를 순회하면서 각각의 bytes 값 배열들을 메모리에서 해제하면 된다.
*/
void
unload_binary(Binary *bin)
{
  size_t i;
  Section *sec;

  for(i = 0; i < bin->sections.size(); i++) {
    sec = &bin->sections[i];
    if(sec->bytes) {
      free(sec->bytes);
    }
  }
}

