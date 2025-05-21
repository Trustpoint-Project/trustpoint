let devicesByOSLineChart, devicesByDomainDonutChart, devicesByOPBarChart;
let certsByStatusLineChart, certsByDomainPieChart, certsByTemplateBarChart;
let certsByDateStackChart, certsByIssuingCADonutChart, issuingCAsByTypePieChart;

function updateCharts(dashboardChartData) {
  //updateDeviceDateChart(dashboardData.device_counts_by_date_and_os);
  updateDeviceByOSBarChart(dashboardChartData.device_counts_by_os);
  updateDeviceByOPBarChart(dashboardChartData.device_counts_by_op);
  updateDevicesByDomainDonutChart(dashboardChartData.device_counts_by_domain);

  updateCertsByDateStackChart(dashboardChartData.cert_counts_by_issuing_ca_and_date);
  updateCertsByDomainPieChart(dashboardChartData.cert_counts_by_domain);
  updateCertsByTemplateBarChart(dashboardChartData.cert_counts_by_template);

  //updateCertsByStatusLineChart(dashboardChartData.cert_counts_by_status);
  updateCertsByStatusBarChart(dashboardChartData.cert_counts_by_status);
  updateCertsByIssuingCAChart(dashboardChartData.cert_counts_by_issuing_ca);
  updateIssuingCAsByTypePieChart(dashboardChartData.ca_counts_by_type);
}

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

// Funktion zum Abrufen der Dashboard-Daten über die Backend-API
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

// Funktion zum Aktualisieren der Dashboard-Daten
async function fetchAndUpdateDashboardData(period) {
  const dashboardData = await fetchDashboardData(period);
  console.log("dashboard data", dashboardData);
  if (dashboardData) {
    if ("device_counts" in dashboardData) {
      updateDeviceCounts(dashboardData.device_counts);
    }
    if ("cert_counts" in dashboardData) {
      updateCertCounts(dashboardData.cert_counts);
    }
    if ("issuing_ca_counts" in dashboardData) {
      updateIssuingCACounts(dashboardData.issuing_ca_counts);
    }
    updateCharts(dashboardData);
  }
}

function toggleChartButtons() {
  const buttons = document.querySelectorAll(".chart-period");
  //console.log("buttons", buttons)
  buttons.forEach((button) => {
    button.addEventListener("click", () => {
      // Remove active class from all buttons
      buttons.forEach((btn) => btn.classList.remove("active"));
      // Add active class to the clicked button
      button.classList.add("active");
    });
  });
}

async function fetchAndUpdateDashboardChartData(period) {
  const dashboardData = await fetchDashboardData(period);
  console.log("dashboard data", dashboardData);
  if (dashboardData) {
    updateCharts(dashboardData);
  }
}

// Funktion zum Abrufen und Anzeigen der Dashboard-Daten aufrufen
fetchAndUpdateDashboardData("today");
toggleChartButtons();
// every 20 seconds
//setInterval(fetchAndUpdateDashboardData, 1000*20);

document.addEventListener("DOMContentLoaded", function () {
  //device charts data from context
  // var stackChartConfig = JSON.parse("{{ line_chart_device_config|escapejs }}");
  // var donutChartDeviceConfig = JSON.parse("{{ donut_chart_device_config|escapejs }}");
  // var barChartDeviceConfig = JSON.parse("{{ bar_chart_device_config|escapejs }}");

  //cert charts data from context
  //var lineChartCertConfig = JSON.parse("{{ line_chart_cert_config|escapejs }}");
  // var donutChartCertConfig = JSON.parse("{{ donut_chart_cert_config|escapejs }}");
  // var barChartCertConfig = JSON.parse("{{ bar_chart_cert_config|escapejs }}");

  // //CA charts data from context
  // var barChartCAConfig = JSON.parse("{{ bar_chart_ca_config|escapejs }}");
  // var lineChartConfig = JSON.parse("{{ line_chart_config|escapejs }}");
  // var donutChartCAConfig = JSON.parse("{{ donut_chart_ca_config|escapejs }}");

  var chartTabEl = document.getElementById("chartTabs");
  var chartTab = new bootstrap.Tab(chartTabEl);
  // Initial update for the active chart tab
  var activeChartTabId = document
    .querySelector("#chartTabs .nav-link.active")
    .getAttribute("href")
    .substring(1);
  updateChartContent(activeChartTabId);

  // Add event listener to the charts tab for the 'shown.bs.tab' event
  chartTabEl.addEventListener("shown.bs.tab", function (event) {
    var targetId = event.target.getAttribute("href").substring(1);
    updateChartContent(targetId);
  });

  // function to update charts content based on chart tab id
  function updateChartContent(chartTabId) {
    if (chartTabId == "deviceChartTab") {
      //var lineChartDeviceEle = document.getElementById("devicesByOSLineChart").getContext("2d");
      //((if (!devicesByOSLineChart) devicesByOSLineChart = new Chart(lineChartDeviceEle, stackChartConfig);
      //var donutChartDeviceEle = document.getElementById("devicesByDomainDonutChart").getContext("2d");
      //if (!devicesByDomainDonutChart)
      //  devicesByDomainDonutChart = new Chart(donutChartDeviceEle, donutChartDeviceConfig);
      //var barChartDeviceEle = document.getElementById("devicesByOPBarChart").getContext("2d");
      //if (!devicesByOPBarChart) devicesByOPBarChart = new Chart(barChartDeviceEle, barChartDeviceConfig);
    } else if (chartTabId == "certChartTab") {
      // var certsByStatusLineChartEle = document
      //   .getElementById("certsByStatusLineChart")
      //   .getContext("2d");
      // if (!certsByStatusLineChart)
      //   certsByStatusLineChart = new Chart(certsByStatusLineChartEle, lineChartCertConfig);
      //var donutChartCertEle = document.getElementById("certsByDomainPieChart").getContext("2d");
      //if (!certsByDomainPieChart) certsByDomainPieChart = new Chart(donutChartCertEle, donutChartCertConfig);
      //var barChartCertEle = document.getElementById("barChartCert").getContext("2d");
      //if (!barChartCert) barChartCert = new Chart(barChartCertEle, barChartCertConfig);
    } else if (chartTabId == "caChartTab") {
      // var lineChartEle = document.getElementById("lineChart").getContext("2d");
      // if(!lineChart)
      //   lineChart = new Chart(lineChartEle, lineChartConfig);
      //var barChartCAEle = document.getElementById("barChartCA").getContext("2d");
      //if (!barChartCA) barChartCA = new Chart(barChartCAEle, barChartCAConfig);
      //var donutChartCAEle = document.getElementById("donutChartCA").getContext("2d");
      //if (!donutChartCA) donutChartCA = new Chart(donutChartCAEle, donutChartCAConfig);
    }
  }
});