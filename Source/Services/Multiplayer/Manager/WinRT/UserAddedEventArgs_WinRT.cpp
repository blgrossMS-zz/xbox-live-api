//*********************************************************
//
// Copyright (c) Microsoft. All rights reserved.
// THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
// IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
// PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************
#pragma once
#include "pch.h"
#include "UserAddedEventArgs_WinRT.h"

using namespace xbox::services::multiplayer::manager;

NAMESPACE_MICROSOFT_XBOX_SERVICES_MULTIPLAYER_MANAGER_BEGIN

UserAddedEventArgs::UserAddedEventArgs(
    _In_ std::shared_ptr<user_added_event_args> cppObj
    ) :
    m_cppObj(cppObj)
{
    XSAPI_ASSERT(cppObj != nullptr);
}

std::shared_ptr<user_added_event_args>
UserAddedEventArgs::GetCppObj() const
{
    return m_cppObj;
}

NAMESPACE_MICROSOFT_XBOX_SERVICES_MULTIPLAYER_MANAGER_END