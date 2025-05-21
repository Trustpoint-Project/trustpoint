// Function to update the device counts
function updateDeviceCounts(deviceCounts) {
  document.getElementById("total-device-count").textContent = `${deviceCounts.total}`;
  document.getElementById("onboared-device-count").textContent = `Onboarded: ${deviceCounts.Onboarded}`;
  document.getElementById("pending-device-count").textContent = `Waiting: ${deviceCounts.Pending}`;

  document.getElementById("onboared-device-progress").style.width = `${
      (deviceCounts.Onboarded * 100) / deviceCounts.total
  }%`;
  document.getElementById("pending-device-progress").style.width = `${
      (deviceCounts.Pending * 100) / deviceCounts.total
  }%`;
}


function updateCertCounts(certCounts) {
  // update certificate count panel
  document.getElementById("total-cert-count").textContent = `${certCounts.total}`;
  document.getElementById("active-cert-count").textContent = `Active: ${certCounts.active}`;
  document.getElementById("expired-cert-count").textContent = `Expired: ${certCounts.expired}`;
  // Update progress bars
  document.getElementById("active-cert-progress").style.width = `${
      (certCounts.active * 100) / certCounts.total
  }%`;
  document.getElementById("expired-cert-progress").style.width = `${
      (certCounts.expired * 100) / certCounts.total
  }%`;

  // update expiring certificate count panel
  document.getElementById(
      "total-expiring-cert-count"
  ).textContent = `${certCounts.expiring_in_7_days}`;
  document.getElementById(
      "expiring-1day-cert-count"
  ).textContent = `Next 24 hours: ${certCounts.expiring_in_1_day}`;
  document.getElementById(
      "expiring-7days-cert-count"
  ).textContent = `Next 7 days: ${certCounts.expiring_in_7_days}`;
  // Update progress bars
  document.getElementById("expiring-1day-cert-progress").style.width = `${
      (certCounts.expiring_in_1_day * 100) / certCounts.total
  }%`;
  document.getElementById("expiring-7days-cert-progress").style.width = `${
      (certCounts.expiring_in_7_days * 100) / certCounts.total
  }%`;
}


// Function to update the issuing ca counts
function updateIssuingCACounts(issuingCACounts) {
  document.getElementById("total-issuing-ca-count").textContent = `${issuingCACounts.total}`;
  document.getElementById(
      "active-issuing-ca-count"
  ).textContent = `Active: ${issuingCACounts.active}`;
  document.getElementById(
      "expired-issuing-ca-count"
  ).textContent = `Expired: ${issuingCACounts.expired}`;
  // Update progress bars
  document.getElementById("active-issuing-ca-progress").style.width = `${
      (issuingCACounts.active * 100) / issuingCACounts.total
  }%`;
  document.getElementById("expired-issuing-ca-progress").style.width = `${
      (issuingCACounts.expired * 100) / issuingCACounts.total
  }%`;
}