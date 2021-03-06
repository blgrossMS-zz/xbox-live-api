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

#include "xsapi/user_statistics.h"

NAMESPACE_MICROSOFT_XBOX_SERVICES_USERSTATISTICS_BEGIN

/// <summary>
/// Contains information about a user statistic.
/// </summary>
public ref class Statistic sealed
{
public:
    /// <summary>
    /// The name of the statistic.
    /// </summary>
    DEFINE_PROP_GET_STR_OBJ(StatisticName, statistic_name);

    /// <summary>
    /// The type of the statistic.
    /// It can be one of the following values:
    /// PropertyType.Int64, PropertyType.Double, 
    /// PropertyType.String, PropertyType.DateTime, 
    /// or PropertyType.OtherType if unknown.
    /// </summary>
    property Windows::Foundation::PropertyType StatisticType { Windows::Foundation::PropertyType get(); }

    /// <summary>
    /// The value of the statistic.
    /// </summary>
    DEFINE_PROP_GET_STR_OBJ(Value, value);

internal:
    Statistic(
        _In_ xbox::services::user_statistics::statistic cppObj
        );

private:
    Windows::Foundation::PropertyType m_statType;
    xbox::services::user_statistics::statistic m_cppObj;
};

NAMESPACE_MICROSOFT_XBOX_SERVICES_USERSTATISTICS_END
