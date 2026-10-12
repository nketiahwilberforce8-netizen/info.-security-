@echo off
title NKETIAH School System - Push Clean Folder Structure to GitHub
echo ============================================================================
echo   NKETIAH SCHOOL MANAGEMENT SYSTEM - GITHUB DEPLOYMENT FIXER
echo ============================================================================
echo.
echo Replacing the flattened files on GitHub with the clean folder structure
echo (api/, backend/, web/, mobile/, vercel.json, package.json, tsconfig.json)...
echo.
"%LOCALAPPDATA%\Programs\MinGit\cmd\git.exe" push -u origin main --force
echo.
echo ============================================================================
echo   DONE! Vercel will now automatically rebuild and deploy cleanly.
echo ============================================================================
pause
