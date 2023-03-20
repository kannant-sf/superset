/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import React from 'react';
import { DataMaskStateWithId, JsonObject } from '@superset-ui/core';
import { useSelector } from 'react-redux';
import { DashboardLayout, RootState } from 'src/dashboard/types';
import crossFiltersSelector from './selectors';
import VerticalCollapse from './VerticalCollapse';

const CrossFiltersVertical = () => {
  const dataMask = useSelector<RootState, DataMaskStateWithId>(
    state => state.dataMask,
  );
  const chartConfiguration = useSelector<RootState, JsonObject>(
    state => state.dashboardInfo.metadata?.chart_configuration,
  );
  const dashboardLayout = useSelector<RootState, DashboardLayout>(
    state => state.dashboardLayout.present,
  );
  const selectedCrossFilters = crossFiltersSelector({
    dataMask,
    chartConfiguration,
    dashboardLayout,
  });

  return <VerticalCollapse crossFilters={selectedCrossFilters} />;
};

export default CrossFiltersVertical;