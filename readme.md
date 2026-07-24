# Secure Coding

## Tiny Secondhand Shopping Platform

Python과 Flask로 구현한 중고거래 플랫폼이다. 회원 관리,
상품 등록, 개인 채팅, 신고 및 관리자 기능과 가상 포인트 기반 안전결제를
제공한다. 일반 사용자는 가입 시 1,000,000포인트를 받고, 구매 금액은 구매
확정 전까지 에스크로 상태로 유지된다.

## 요구 환경

- Miniconda 또는 Anaconda
- Git
- 인터넷 연결: 최초 Conda 환경 생성 및 pip 패키지 다운로드에 필요
- 지원 운영체제: Windows, Linux, macOS

Miniconda가 없다면
[Miniconda 설치 안내](https://docs.anaconda.com/miniconda/install/)에 따라
설치한다. 설치 후 새 터미널에서 다음 명령이 실행되는지 확인한다.

```text
conda --version
```

## 프로젝트 내려받기

```text
git clone https://github.com/FriedGD/tiny-2nd-hand.git
cd tiny-2nd-hand
```

## Conda 실행 환경 구축

```text
conda env create -f enviroments.yaml
conda activate secure_coding
```


## 로컬 개발 서버 실행

애플리케이션은 기본적으로 운영환경 설정을 사용한다. 로컬 HTTP 개발에서는
반드시 `APP_ENV=development`를 설정한다. `SECRET_KEY`는 개발환경에서도
매번 바뀌지 않는 충분히 길고 무작위한 값을 사용하는 것이 좋다.

### Windows PowerShell

```powershell
conda activate secure_coding
$env:APP_ENV = "development"
$env:SECRET_KEY = "replace-with-a-long-random-development-secret"
python app.py
```

### Linux/macOS

```bash
conda activate secure_coding
export APP_ENV="development"
export SECRET_KEY="replace-with-a-long-random-development-secret"
python app.py
```

## 최초 관리자 생성

새로 가입한 사용자는 항상 일반 사용자로 생성된다. 역할 관리 폼을 외부에
노출하지 않고 최초 관리자를 만들려면 다음 절차를 따른다.

1. `ADMIN_USERNAME` 없이 애플리케이션을 실행한다.
2. 관리자로 사용할 일반 계정을 가입시킨다.
3. 애플리케이션을 종료한다.
4. `ADMIN_USERNAME`을 기존 사용자명으로 설정하고 다시 실행한다.

Windows PowerShell:

```powershell
$env:ADMIN_USERNAME = "existing-admin-user"
python app.py
```

Linux/macOS:

```bash
export ADMIN_USERNAME="existing-admin-user"
python app.py
```
