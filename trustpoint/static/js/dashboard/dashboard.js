// Helper function to format a date as YYYY-MM-DD
function formatDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0"); // Months are 0-based
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function generateDate(period) {
  // Get today's date
  const today = new Date();
  var periodStartDate = today;
  if (period === "today") {
    periodStartDate = today;
  } else if (period === "last_week") {
    periodStartDate.setDate(today.getDate() - 7);
  } else if (period === "last_month") {
    periodStartDate.setMonth(today.getMonth() - 1);
  } else {
    periodStartDate = new Date("2023-01-01");
  }

  return formatDate(periodStartDate);
}

// Fetch dashboard data for a given period from the server backend API
async function fetchDashboardData(period) {
  try {
    const formattedStartDate = generateDate(period);
    console.log("date", formattedStartDate);
    const response = await fetch(`/home/dashboard_data?start_date=${formattedStartDate}`);
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
      fetchDashboardData('today'),
      fetchDashboardData('last_week'),
      fetchDashboardData('total')
    ]);

    // debug
    console.log("todayData", todayData);
    console.log("weekData", weekData);
    console.log("totalData", totalData);

    const event = new CustomEvent('dashboardData', {
      detail:{
        today: todayData,
        week: weekData,
        total: totalData
      }
    });

    document.dispatchEvent(event);
  }catch(error){
    console.log("Error loadDashboardEvent", error)
  }
}

function createHorizontalBarChart(
  labels,
  values,
  canvasId,
  legendId,
  chartInstanceName
) {
  // Validation of input parameters
  if (!Array.isArray(labels) || !Array.isArray(values)) {
    console.error('Invalid data: labels and values must be arrays');
    return;
  }

  if (labels.length !== values.length) {
    console.error('Invalid data: labels and values must be arrays of equal length');
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

  const allItems = labels
    .map((label, index) => ({
      label,
      value: Number(values[index]) || 0
    }))
    .filter(item => item.value > 0)
    .sort((a, b) => b.value - a.value);

  // Important: Chart is created even when allItems is empty.
  // The plugin then handles the "No Data" display.
  const chartDisplayItems = allItems.slice(0, 5);

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

  // HTML Legend Plugin
  const htmlLegend = {
    id: `htmlLegend${chartInstanceName}`,
    afterUpdate(chart) {
      const container = legendEl;
      if (!container) return;

      container.innerHTML = '';
      const ul = document.createElement('ul');
      ul.className = 'list-unstyled small mb-0';

      allItems.forEach((item, idx) => {
        const li = document.createElement('li');
        li.className = 'd-flex align-items-center mb-1';

        const dot = document.createElement('span');
        dot.className = 'rounded-circle d-inline-block me-2 flex-shrink-0';
        dot.style.width = '10px';
        dot.style.height = '10px';
        dot.style.background = colorForIndex(idx);

        const text = document.createElement('span');
        text.textContent = `${item.label} (${item.value})`;

        li.append(dot, text);
        ul.appendChild(li);
      });

      container.appendChild(ul);
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
      labels: chartDisplayItems.map(i => i.label),
      datasets: [{
        data: chartDisplayItems.map(i => i.value),
        backgroundColor: chartDisplayItems.map((_, i) => colorForIndex(i)),
        borderColor: 'transparent',
        borderRadius: 12,
        barPercentage: 0.6,
        categoryPercentage: 0.7
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: 'y',
      scales: {
        x: {
          beginAtZero: true,
          grid: { color: 'rgba(0,0,0,0.06)' },
          ticks: { precision: 0 }
        },
        y: {
          grid: { display: false }
        }
      },
      plugins: {
        legend: { display: false },

        // 👇 Here you configure the No-Data plugin
        noDataImagePlugin: {
          imageSrc: 'trustpoint/static/img/tp-logo-128.png',
          text: 'No Data'
        }
      }
    },
    plugins: [valueLabels, htmlLegend, noDataImagePlugin]
  });

  return window[chartInstanceKey];
}

const noDataImagePlugin = {
  id: 'noDataImagePlugin',
  afterDraw(chart, args, pluginOptions) {
    const opts = pluginOptions || {};
    const imageSrc = opts.imageSrc;
    const text = opts.text || 'No Data';

    // Check if there is any meaningful data
    const hasData =
      chart.data &&
      chart.data.datasets &&
      chart.data.datasets.length > 0 &&
      chart.data.datasets.some(ds =>
        Array.isArray(ds.data) && ds.data.some(v => v != null && v !== 0)
      );

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

      const maxImgWidth = width * 0.6;
      const imgWidth = Math.min(img.width, maxImgWidth);
      const imgHeight = (imgWidth / img.width) * img.height;

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
}

function createDonutChart(data, canvasId, chartInstanceName, options = {}) {
  const colors = ['#0B5ED7', '#86B7FE', '#E9ECEF'];
  const showLegend = true;
  const {
    centerText = 'Certificates',
    labels = ['Active Certificates', 'Expiring Certificates', 'Expired Certificates']
  } = options;


  const { active, expiring, expired, total } = data;
  
  const centerTextPlugin = {
    id: `centerText${chartInstanceName}`,
    afterDraw(chart) {
      const meta = chart.getDatasetMeta(0);
      if (!meta?.data?.length) return;
      const { ctx } = chart;
      const { x, y } = meta.data[0];

      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';

      // Number
      ctx.font = '600 36px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bs-body-color') || '#000';
      ctx.fillText(total, x, y - 8);

      // Subtitle
      ctx.font = '500 12px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.globalAlpha = 0.85;
      ctx.fillText(centerText, x, y + 16);
      ctx.restore();
    }
  };

  const noDataPlugin = {
    id:'noDataPlugin',
    afterDraw: (chart) => {
      if (chart.data.datasets.length > 0) return;
      const ctx = chart.ctx;
      const width = chart.width;
      const height = chart.height;

      chart.clear();

      ctx.save();
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.font = '600 36px system-ui, -apple-system, Segoe UI, Roboto, Arial';
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--bs-body-color') || '#000';
      ctx.fillText('No data available', width / 2, height / 2 - 30);

      const img = new Image();
      img.onload = function(){
        const imgSize = 80;
        const x = width/2-imgSize/2;
        const y = height/2+10;
        ctx.drawImage(img, x, y, imgSize, imgSize);
      };
      img.src = '../../static/img/tp-logo-128.png';
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
        data: [active, expiring, expired],
        backgroundColor: colors,
        borderColor: 'transparent',
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
          display: showLegend,
          position: 'bottom',
          align: 'start',
          labels: {
            usePointStyle: true,
            pointStyle: 'circle',
            boxWidth: 10,
            boxHeight: 10,
            padding: 14,
            color: '#6c757d',
            font: { size: 12 }
          }
        },
        tooltip: {
          callbacks: {
            label: (context) => {
              const value = context.parsed || 0;
              const percentage = total ? Math.round((value / total) * 100) : 0;
              return `${context.label}: ${value} (${percentage}%)`;
            }
          }
        }
      }
    },
    plugins: [centerTextPlugin, noDataPlugin]
  });

  return window[chartInstanceKey];
}

document.addEventListener("DOMContentLoaded", loadDashboardData)