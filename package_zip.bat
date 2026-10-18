@echo off
echo Packaging Rover Watch v1.0.2 for Chrome and Firefox...

:: 1. Save copy of primary Chrome manifest
copy /y manifest.json manifest.chrome.json >nul

:: 2. Archive previous Chrome build to .bak if it exists
if exist rover-watch-chrome-v1.0.2.zip (
    echo Archiving previous Chrome package to rover-watch-chrome-v1.0.2.zip.bak...
    copy /y rover-watch-chrome-v1.0.2.zip rover-watch-chrome-v1.0.2.zip.bak >nul
    del rover-watch-chrome-v1.0.2.zip
)

:: Build Chrome Package including icons folder
powershell -Command "$files = Get-ChildItem -Path content.js, background.js, manifest.json, popup.html, icons -ErrorAction SilentlyContinue; Compress-Archive -Path $files.FullName -DestinationPath rover-watch-chrome-v1.0.2.zip -Force"
echo Chrome zip created: rover-watch-chrome-v1.0.2.zip

echo ----------------------------------------------------

:: 3. Archive previous Firefox build to .bak if it exists
if exist rover-watch-firefox-v1.0.2.zip (
    echo Archiving previous Firefox package to rover-watch-firefox-v1.0.2.zip.bak...
    copy /y rover-watch-firefox-v1.0.2.zip rover-watch-firefox-v1.0.2.zip.bak >nul
    del rover-watch-firefox-v1.0.2.zip
)

:: Swap manifest and Build Firefox Package
copy /y manifest.firefox.json manifest.json >nul
powershell -Command "$files = Get-ChildItem -Path content.js, background.js, manifest.json, popup.html, icons -ErrorAction SilentlyContinue; Compress-Archive -Path $files.FullName -DestinationPath rover-watch-firefox-v1.0.2.zip -Force"
echo Firefox zip created: rover-watch-firefox-v1.0.2.zip

:: Restore primary Chrome manifest.json
copy /y manifest.chrome.json manifest.json >nul
del manifest.chrome.json >nul
echo Restored Chrome manifest.json successfully!

echo ----------------------------------------------------
echo Done! All builds packaged and previous versions backed up.