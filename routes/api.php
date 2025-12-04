<?php

use App\Http\Controllers\AuthorizeCreationController;
use App\Http\Controllers\BankController;
use App\Http\Controllers\ConnectivityTestController;
use App\Http\Controllers\EddaStatusController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');

Route::get('/banks', [BankController::class, 'index']);
Route::get('/connectivity-test', [ConnectivityTestController::class, 'index']);
Route::get('/authorize-creation', [AuthorizeCreationController::class, 'createAuthorize']);
Route::get('/edda/status', [EddaStatusController::class, 'getStatus']);