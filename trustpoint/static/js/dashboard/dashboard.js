function formatDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function generatePeriodDate(period) {
  const today = new Date();
  const periodStartDate = new Date(today);
  if (period === "today") {
    return formatDate(periodStartDate);
  } else if (period === "last_week") {
    periodStartDate.setDate(periodStartDate.getDate() - 7);
  } else if (period === "last_month") {
    periodStartDate.setMonth(periodStartDate.getMonth() - 1);
  } else {
    return "2023-01-01";
  }

  return formatDate(periodStartDate);
}

function generateReferenceDate(preset) {
  const today = new Date();
  const referenceDate = new Date(today);

  if (preset === "in_7_days") {
    referenceDate.setDate(referenceDate.getDate() + 7);
  } else if (preset === "in_30_days") {
    referenceDate.setDate(referenceDate.getDate() + 30);
  }

  return formatDate(referenceDate);
}

function getDashboardRequestParams(filterType, preset = "", options = {}) {
  if (filterType === "date_range") {
    const params = {};

    if (options.startDate) {
      params.start_date = options.startDate;
    }

    if (options.endDate) {
      params.end_date = options.endDate;
    }

    return params;
  }

  if (filterType === "period") {
    return { start_date: generatePeriodDate(preset) };
  }

  if (filterType === "as_of") {
    return { reference_date: generateReferenceDate(preset) };
  }

  return {};
}

async function fetchDashboardData(requestParams = {}) {
  try {
    const queryParams = new URLSearchParams();

    Object.entries(requestParams).forEach(([key, value]) => {
      if (value) {
        queryParams.set(key, value);
      }
    });

    const queryString = queryParams.toString();
    const url = queryString ? `/home/dashboard_data?${queryString}` : "/home/dashboard_data";
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error fetching dashboard data:", error);
    return null;
  }
}

function updateDeltaIcon(id, value) {
  const valueEl = document.getElementById(id);
  if (!valueEl) return;

  const iconEl = valueEl.nextElementSibling;
  if (!iconEl) return;

  const num = parseFloat(value);

  if (num > 0) {
    iconEl.classList.remove("bi-caret-down-fill", "bi-dash-lg");
    iconEl.classList.add("bi-caret-up-fill");
  } else if (num < 0) {
    iconEl.classList.remove("bi-caret-up-fill", "bi-dash-lg");
    iconEl.classList.add("bi-caret-down-fill");
  } else {
    iconEl.classList.remove("bi-caret-up-fill", "bi-caret-down-fill");
    iconEl.classList.add("bi-dash-lg");
  }
}

async function loadDashboardData(){
  try{
    const [todayData, weekData, totalData] = await Promise.all([
      fetchDashboardData({ start_date: generatePeriodDate('today') }),
      fetchDashboardData({ start_date: generatePeriodDate('last_week') }),
      fetchDashboardData({ start_date: generatePeriodDate('total') })
    ]);

    const event = new CustomEvent('dashboardData', {
      detail:{
        today: todayData,
        week: weekData,
        total: totalData
      }
    });

    document.dispatchEvent(event);
  }catch(error){
    console.error("Error loadDashboardEvent", error)
  }
}

function normalizeChartValue(value) {
  const numericValue = Number(value);
  return Number.isFinite(numericValue) ? numericValue : 0;
}

function getVisibleChartValues(chart) {
  const dataset = chart?.data?.datasets?.[0];
  if (!dataset || !Array.isArray(dataset.data)) {
    return [];
  }

  return dataset.data
    .map((value, index) => {
      if (typeof chart.getDataVisibility === 'function' && !chart.getDataVisibility(index)) {
        return 0;
      }
      return normalizeChartValue(value);
    });
}

function getVisibleChartTotal(chart) {
  return getVisibleChartValues(chart).reduce((sum, value) => sum + value, 0);
}

function hasVisibleChartData(chart) {
  return getVisibleChartValues(chart).some(value => value > 0);
}

function toggleChartItemVisibility(chart, index, hiddenIndices = null) {
  if (!chart || index == null || typeof chart.toggleDataVisibility !== 'function') {
    return;
  }

  chart.toggleDataVisibility(index);

  if (hiddenIndices) {
    if (chart.getDataVisibility(index)) {
      hiddenIndices.delete(index);
    } else {
      hiddenIndices.add(index);
    }
  }

  chart.update();
}

function applyHiddenIndices(chart, hiddenIndices) {
  if (!chart || !hiddenIndices?.size || typeof chart.toggleDataVisibility !== 'function') {
    return;
  }

  hiddenIndices.forEach((index) => {
    if (chart.getDataVisibility(index)) {
      chart.toggleDataVisibility(index);
    }
  });

  chart.update();
}

function renderBarLegend(legendEl, items, hiddenIndices, colorForIndex, onToggle) {
  if (!legendEl) {
    return;
  }

  legendEl.innerHTML = '';

  if (!items.length) {
    return;
  }

  const ul = document.createElement('ul');
  ul.className = 'list-unstyled small mb-0';

  items.forEach((item, index) => {
    const li = document.createElement('li');
    li.className = 'mb-1';

    const button = document.createElement('button');
    button.type = 'button';
    button.className = `bar-chart-legend-item${hiddenIndices.has(index) ? ' is-hidden' : ''}`;
    button.addEventListener('click', () => onToggle(index));

    const dot = document.createElement('span');
    dot.className = 'rounded-circle d-inline-block flex-shrink-0';
    dot.style.width = '10px';
    dot.style.height = '10px';
    dot.style.background = colorForIndex(index);

    const text = document.createElement('span');
    text.textContent = `${item.label} (${item.value})`;

    button.append(dot, text);
    li.appendChild(button);
    ul.appendChild(li);
  });

  legendEl.appendChild(ul);
}

function createHorizontalBarChart(
  items,
  canvasId,
  legendId,
  chartInstanceName,
  hiddenIndices,
  onToggle
) {
  // Farben immer beim Zeichnen neu auslesen
  const style = getComputedStyle(document.documentElement);
  const gridColor = style.getPropertyValue('--chart-grid-color').trim() || 'rgba(222, 226, 230, 0.2)';
  const borderColor = style.getPropertyValue('--chart-border-color').trim() || '#dee2e6';
  const textColor = style.getPropertyValue('--chart-text-color').trim() || '#dee2e6';

  // Validation of input parameters
  if (!Array.isArray(items)) {
    console.error('Invalid data: items must be an array');
    return;
  }

  if (!canvasId || !legendId) {
    console.error('Canvas ID and Legend ID are required');
    return;
  }

  const canvasEl = document.getElementById(canvasId);
  const legendEl = document.getElementById(legendId);

  if (!canvasEl) {
    console.error(`Canvas element with ID '${canvasId}' not found`);
    return;
  }

  const visibleItems = items.filter((item) => !hiddenIndices.has(item.sourceIndex));
  // The plugin then handles the "No Data" display.
  const hasData = visibleItems.length > 0;

  const palette = [
    '#0B5ED7', '#86B7FE', '#A6C8FF',
    '#CFE2FF', '#6C757D', '#ADB5BD', '#E9ECEF'
  ];
  const colorForIndex = (i) => palette[i % palette.length];

  // Value Labels Plugin
  const valueLabels = {
    id: `valueLabels${chartInstanceName}`,
    afterDatasetsDraw(chart) {
      const { ctx } = chart;
      const ds = chart.data.datasets[0];
      const meta = chart.getDatasetMeta(0);

      meta.data.forEach((bar, i) => {
        const val = ds.data[i];
        if (val == null) return;

        ctx.save();
        ctx.font = '600 12px system-ui,-apple-system,Segoe UI,Roboto,Arial';
        ctx.fillStyle =
          getComputedStyle(document.documentElement)
            .getPropertyValue('--bs-body-color') || '#000';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(String(val), bar.x + 6, bar.y);
        ctx.restore();
      });
    }
  };

  // Destroy old chart if it exists
  const chartInstanceKey = `_${chartInstanceName}Chart`;
  if (window[chartInstanceKey]) {
    window[chartInstanceKey].destroy();
  }

  // Create new chart
  window[chartInstanceKey] = new Chart(canvasEl, {
    type: 'bar',
    data: {
      labels: visibleItems.map(i => i.label),
      datasets: [{
        data: visibleItems.map(i => i.value),
        backgroundColor: visibleItems.map((item) => colorForIndex(item.sourceIndex)),
        borderColor: 'transparent',
        borderRadius: 12,
        barPercentage: 0.6,
        categoryPercentage: 0.7
      }]
    },
    options: {
      layout: {
        padding: {
          right: hasData ? 40 : 0
        }        
      },
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: {
          display: hasData,
          beginAtZero: true,
          grid: { 
            color: gridColor 
          },
          border: {
            display: true,
            color: borderColor 
          },
          ticks: { 
            precision: 0, 
            color: textColor 
          }
        },
        y: {
          display: hasData,
          grid: { display: false },
          border: {
            display: true,
            color: borderColor 
          },
          ticks: { 
            color: textColor 
          }
        }
      },
      plugins: {
        legend: { display: false },
        // 👇 Here you configure the No-Data plugin
        noDataImagePlugin: {
          text: 'No Data'
        }
      }
    },
    plugins: [valueLabels, noDataImagePlugin]
  });

  renderBarLegend(legendEl, items, hiddenIndices, colorForIndex, onToggle);

  return window[chartInstanceKey];
}

const noDataImagePlugin = {
  id: 'noDataImagePlugin',
  afterDraw(chart, args, pluginOptions) {
    const opts = pluginOptions || {};
    const imageSrc = opts.imageSrc;
    const text = opts.text ?? 'No Data';

    // Check if there is any meaningful data
    const hasData = hasVisibleChartData(chart);

    if (hasData) return;

    const { ctx, chartArea } = chart;
    if (!chartArea) return;

    const { left, top, right, bottom } = chartArea;
    const width = right - left;
    const height = bottom - top;

    ctx.save();
    // Clear drawing area so no axes etc. interfere
    ctx.clearRect(left, top, width, height);

    const drawTextOnly = () => {
      ctx.save();
      ctx.font = '500 14px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.fillStyle = '#6c757d';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(text, left + width / 2, top + height / 2);
      ctx.restore();
    };

    if (!imageSrc) {
      drawTextOnly();
      ctx.restore();
      return;
    }

    // Image caching in plugin options object
    if (!opts._img) {
      const img = new Image();
      img.src = imageSrc;
      opts._img = img;
      opts._imgLoaded = false;

      img.onload = () => {
        opts._imgLoaded = true;
        chart.draw(); // Reload → Redraw canvas
      };
      img.onerror = () => {
        opts._imgLoaded = false;
      };
    }

    if (opts._img && opts._imgLoaded) {
      const img = opts._img;

      // Constrain to 50% of container dimensions to ensure it fits
      const scale = Math.min((width * 0.5) / img.width, (height * 0.5) / img.height);

      const imgWidth = img.width * scale;
      const imgHeight = img.height * scale;

      const x = left + (width - imgWidth) / 2;
      const y = top + (height - imgHeight) / 2 - 10;

      ctx.drawImage(img, x, y, imgWidth, imgHeight);

      // Optional text below
      ctx.save();
      ctx.font = '500 14px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.fillStyle = '#6c757d';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(text, left + width / 2, y + imgHeight + 8);
      ctx.restore();
    } else {
      // While the image is not yet loaded → Show text
      drawTextOnly();
    }

    ctx.restore();
  }
};

function createDonutChart(data, canvasId, chartInstanceName, options = {}, hiddenIndices = new Set()) {
  // Dynamically read colors
  const style = getComputedStyle(document.documentElement);
  const textColor = style.getPropertyValue('--chart-text-color').trim() || '#dee2e6';

  const colorMap = {
    no_onboarding: '#198754',
    pending: '#CFE2FF',
    onboarded: '#0B5ED7',
    none: '#E9ECEF',
    valid: '#0B5ED7',
    active: '#198754',
    expiring: '#DC3545',
    expired: '#ADB5BD'
  };

  const showLegend = true;
  const {
    centerText = 'Certificates',
    labels = ['Active Certificates', 'Expiring Certificates', 'Expired Certificates'],
    dataKeys = ['active', 'expiring', 'expired']
  } = options;

  const chartDataArray = dataKeys.map((key) => normalizeChartValue(data[key]));
  const hasData = chartDataArray.some(value => normalizeChartValue(value) > 0);

  // Use light pink gradient for expiring instead of blue
  const chartColors = dataKeys.map(key => key === 'expiring' ? '#FFE8E8' : (colorMap[key] || '#0B5ED7'));
  // Create border colors - light pink for expiring, transparent for others
  const borderColors = dataKeys.map(key => key === 'expiring' ? '#FFB3B3' : 'transparent');

  const centerTextPlugin = {
    id: `centerText${chartInstanceName}`,
    afterDraw(chart) {
      const visibleTotal = getVisibleChartTotal(chart);
      if (!visibleTotal) return;

      const meta = chart.getDatasetMeta(0);
      if (!meta?.data?.length) return;
      const { ctx } = chart;
      const { x, y } = meta.data[0];

      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // Subtitle
      ctx.font = '600 36px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      const currentTextColor = getComputedStyle(document.documentElement)
        .getPropertyValue('--bs-body-color') || '#000';
      ctx.fillStyle = currentTextColor;
      ctx.fillText(visibleTotal, x, y - 8);

      // Subtitle
      ctx.font = '500 12px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.globalAlpha = 0.85;
      ctx.fillText(centerText, x, y + 16);
      ctx.restore();
    }
  };

  // Destroy old chart
  const chartInstanceKey = `_${chartInstanceName}Chart`;
  if (window[chartInstanceKey]) {
    window[chartInstanceKey].destroy();
  }

  const ctx = document.getElementById(canvasId);
  if (!ctx) {
    console.error(`Canvas element with ID '${canvasId}' not found`);
    return;
  }

  window[chartInstanceKey] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: chartDataArray,
        backgroundColor: chartColors,
        borderColor: borderColors,
        borderWidth: 2,
        borderRadius: 5,
        spacing: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          display: showLegend && hasData,
          position: 'bottom',
          align: 'start',
          onClick: (_event, legendItem, legend) => {
            toggleChartItemVisibility(legend.chart, legendItem.index, hiddenIndices);
          },
          onHover: (event) => {
          event.native.target.style.cursor = 'pointer';
          },
          onLeave: (event) => {
          event.native.target.style.cursor = 'default';
          },
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 10,
            boxHeight: 10,
            padding: 14,
            color: textColor,
            font: { size: 12 }
          }
        },
        noDataImagePlugin: { 
          text: 'No Data' 
        },
        tooltip: {
          callbacks: {
            label: (context) => {
              const value = context.parsed || 0;
              const visibleTotal = getVisibleChartTotal(context.chart);
              const percentage = visibleTotal ? Math.round((value / visibleTotal) * 100) : 0;
              return `${context.label}: ${value} (${percentage}%)`;
            }
          }
        }
      }
    },
    plugins: [centerTextPlugin, noDataImagePlugin]
  });

  applyHiddenIndices(window[chartInstanceKey], hiddenIndices);

  return window[chartInstanceKey];
}

document.addEventListener("DOMContentLoaded", loadDashboardData)

function getDonutChartConfig(datasetName, chartTitle) {
  const chartConfigs = {
    device_enrollment_counts: {
      centerText: chartTitle,
      dataKeys: ['no_onboarding', 'pending', 'onboarded'],
      labels: ['No Onboarding', 'Pending', 'Onboarded'],
    },
    device_domain_credential_counts: {
      centerText: chartTitle,
      dataKeys: ['none', 'valid', 'expiring', 'expired'],
      labels: ['No Domain Credentials', 'Valid Domain Credentials', 'Expiring Domain Credentials', 'Expired Domain Credentials'],
    },
    device_application_certificate_counts: {
      centerText: chartTitle,
      dataKeys: ['none', 'active', 'expired'],
      labels: ['No Application Certificates', 'Active Application Certificates', 'Expired Application Certificates'],
    },
    cert_counts: {
      centerText: chartTitle,
      dataKeys: ['active', 'expiring', 'expired'],
      labels: ['Active Certificates', 'Expiring Certificates', 'Expired Certificates'],
      mapData: (sourceData) => ({
        active: sourceData.active || 0,
        expiring: (sourceData.expiring_in_1_day || 0) + (sourceData.expiring_in_7_days || 0) + (sourceData.expiring_in_30_days || 0),
        expired: sourceData.expired || 0,
      }),
    },
    issuing_ca_counts: {
      centerText: chartTitle,
      dataKeys: ['active', 'expiring', 'expired'],
      labels: ['Active Issuing CAs', 'Expiring Issuing CAs', 'Expired Issuing CAs'],
      mapData: (sourceData) => ({
        active: sourceData.active || 0,
        expiring: (sourceData.expiring_in_1_day || 0) + (sourceData.expiring_in_7_days || 0) + (sourceData.expiring_in_30_days || 0),
        expired: sourceData.expired || 0,
      }),
    },
  };

  return chartConfigs[datasetName] || {
    centerText: chartTitle,
    dataKeys: ['active', 'expiring', 'expired'],
    labels: ['Active', 'Expiring', 'Expired'],
  };
}

function getBarChartConfig(datasetName, dataVariant = "default") {
  const expiringWindowItems = (sourceData) => ([
    { label: "24 Hours", value: sourceData.expiring_in_1_day || 0 },
    { label: "2-7 Days", value: sourceData.expiring_in_7_days || 0 },
    { label: "8-30 Days", value: sourceData.expiring_in_30_days || 0 },
  ]);

  const mapArrayItems = (sourceData) => sourceData.map(item => {
    const labelKey = Object.keys(item).find(key => key.includes('name'));
    const valueKey = Object.keys(item).find(key => key.includes('count'));
    return {
      label: labelKey ? item[labelKey] : 'Unknown',
      value: valueKey ? item[valueKey] : 0
    };
  });

  const mapObjectItems = (sourceData) => Object.entries(sourceData).map(([key, value]) => ({
    label: key || 'Unknown',
    value: value || 0
  }));

  const chartConfigs = {
    "cert_counts_by_issuing_ca:default": { mapData: mapArrayItems },
    "cert_counts_by_status:default": { mapData: mapObjectItems },
    "cert_counts_by_profile:default": { mapData: mapObjectItems },
    "device_counts_by_op:default": { mapData: mapObjectItems },
    "device_counts_by_domain:default": { mapData: mapArrayItems },
    "cert_counts:expiring_window": { mapData: expiringWindowItems, limit: 3, sortItems: false },
    "device_dashboard_counts:expiring_window": { mapData: expiringWindowItems, limit: 3, sortItems: false },
    "expiring_application_certificate_counts:expiring_window": { mapData: expiringWindowItems, limit: 3, sortItems: false },
    "issuing_ca_counts:expiring_window": { mapData: expiringWindowItems, limit: 3, sortItems: false },
  };

  return chartConfigs[`${datasetName}:${dataVariant}`] || {
    mapData: (sourceData) => Array.isArray(sourceData) ? mapArrayItems(sourceData) : mapObjectItems(sourceData || {}),
    limit: 5,
  };
}

function buildBarChartItems(dataSource, datasetName, dataVariant = "default") {
  const config = getBarChartConfig(datasetName, dataVariant);
  const items = config.mapData(Array.isArray(dataSource) ? dataSource : (dataSource || {}))
    .map((item) => ({
      label: item.label || 'Unknown',
      value: normalizeChartValue(item.value),
    }))
    .filter((item) => item.value > 0);

  const orderedItems = config.sortItems === false
    ? items
    : items.sort((a, b) => b.value - a.value);

  return orderedItems
    .slice(0, config.limit || 5)
    .map((item, index) => ({
      ...item,
      sourceIndex: index,
    }));
}

function initializeBarChart(identifier, dataset, filterType = "", defaultPreset = "", dataVariant = "default") {
  const chartCanvasId = `chart_${identifier}`;
  const legendContainerId = `legend_${identifier}`;
  const filterSelect = document.getElementById(`chart_filter_${identifier}`);
  const startDateInput = document.getElementById(`chart_filter_start_${identifier}`);
  const endDateInput = document.getElementById(`chart_filter_end_${identifier}`);
  const applyButton = document.getElementById(`chart_filter_apply_${identifier}`);
  const resetButton = document.getElementById(`chart_filter_reset_${identifier}`);

  let chartInstance = null;
  let chartItems = [];
  const hiddenIndices = new Set();

  function drawChart() {
    if (chartInstance && typeof chartInstance.destroy === 'function') {
      chartInstance.destroy();
    }

    chartInstance = createHorizontalBarChart(
      chartItems,
      chartCanvasId,
      legendContainerId,
      identifier,
      hiddenIndices,
      (index) => {
        if (hiddenIndices.has(index)) {
          hiddenIndices.delete(index);
        } else {
          hiddenIndices.add(index);
        }
        drawChart();
      }
    );
  }

  function updateChartItems(responseData) {
    const sourceData = responseData?.[dataset] || [];
    chartItems = buildBarChartItems(sourceData, dataset, dataVariant);
    hiddenIndices.clear();
    drawChart();
  }

  if (filterType === 'date_range' && startDateInput && endDateInput) {
    const loadDateRangeChart = async () => {
      const responseData = await fetchDashboardData(
        getDashboardRequestParams(filterType, '', {
          startDate: startDateInput.value,
          endDate: endDateInput.value,
        })
      );
      updateChartItems(responseData || {});
    };

    const applyDateRange = () => {
      loadDateRangeChart();
    };

    applyButton?.addEventListener('click', applyDateRange);
    resetButton?.addEventListener('click', () => {
      startDateInput.value = '';
      endDateInput.value = '';
      loadDateRangeChart();
    });

    [startDateInput, endDateInput].forEach((input) => {
      input.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          applyDateRange();
        }
      });
    });

    loadDateRangeChart();
  } else if (filterType && filterSelect) {
    const loadFilteredChart = async () => {
      const responseData = await fetchDashboardData(
        getDashboardRequestParams(filterType, filterSelect.value || defaultPreset)
      );
      updateChartItems(responseData || {});
    };

    filterSelect.addEventListener('change', loadFilteredChart);
    loadFilteredChart();
  } else {
    document.addEventListener('dashboardData', (event) => {
      const total = event.detail.total || {};
      updateChartItems(total);
    });
  }

const observer = new MutationObserver(() => {
  drawChart(); 
});
observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });
}

function initializeDonutChart(identifier, datasetName, chartTitle, filterType = "", defaultPreset = "") {
  const chartCanvasId = `chart_dount_${identifier}`;
  const filterSelect = document.getElementById(`chart_filter_${identifier}`);
  
  let chartInstance = null;
  let chartData = null;
  let chartOptions = null;
  const hiddenIndices = new Set();

  function drawChart() {
    if (chartInstance && typeof chartInstance.destroy === 'function') {
      chartInstance.destroy();
    }
    if (chartData) {
      chartInstance = createDonutChart(chartData, chartCanvasId, identifier, chartOptions, hiddenIndices);
    }
  }

  function updateChartData(responseData) {
    const sourceData = responseData?.[datasetName] || {};
    const config = getDonutChartConfig(datasetName, chartTitle);

    if (!Array.isArray(sourceData)) {
      chartData = config.mapData ? config.mapData(sourceData) : sourceData;
      chartOptions = {
        centerText: config.centerText,
        labels: config.labels,
        dataKeys: config.dataKeys,
      };
    }
    hiddenIndices.clear();
    
    drawChart();
  }

  if (filterType && filterSelect) {
    const loadFilteredChart = async () => {
      const responseData = await fetchDashboardData(
        getDashboardRequestParams(filterType, filterSelect.value || defaultPreset)
      );
      updateChartData(responseData || {});
    };

    filterSelect.addEventListener('change', loadFilteredChart);
    loadFilteredChart();
  } else {
    document.addEventListener("dashboardData", (event) => {
      const today = event.detail.today || {};
      updateChartData(today);
    });
  }

const observer = new MutationObserver(() => {
  drawChart(); 
});
observer.observe(document.documentElement, { attributes: true, attributeFilter: ['data-bs-theme'] });
}
