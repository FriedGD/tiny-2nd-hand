# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ugonfor/secure-coding
conda env create -f enviroments.yaml
```

## usage

The application uses production-safe cookie settings by default. For local HTTP development, explicitly set `APP_ENV=development`. Production requires a strong, stable `SECRET_KEY` and enables Secure session cookies.

PowerShell:

```
$env:APP_ENV = "development"
$env:SECRET_KEY = "replace-with-a-long-random-value"
python app.py
```

Linux/macOS:

```
export APP_ENV="development"
export SECRET_KEY="replace-with-a-long-random-value"
python app.py
```

For an HTTPS production deployment, omit `APP_ENV` (or set it to `production`) and always provide `SECRET_KEY`. Optional comma-separated cross-origin form origins can be configured with `ALLOWED_ORIGINS`; same-origin requests are allowed automatically.

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```
