/**
 * SentinelSOC Custom DataTables Wrapper
 */
const Tables = {
  /**
   * Initialize a DataTable with standard enterprise configurations
   * @param {string|HTMLElement} selector - Table element selector
   * @param {object} options - DataTables config options
   */
  init(selector, options = {}) {
    const defaultOptions = {
      responsive: true,
      pageLength: 20,
      lengthMenu: [10, 20, 50, 100],
      dom: 'Bfrtip',
      buttons: [
        {
          extend: 'csv',
          text: '<i class="fa-solid fa-file-csv mr-1"></i> Export CSV',
          className: 'dt-button'
        },
        {
          extend: 'excel',
          text: '<i class="fa-solid fa-file-excel mr-1"></i> Export Excel',
          className: 'dt-button'
        },
        {
          extend: 'colvis',
          text: '<i class="fa-solid fa-columns mr-1"></i> Columns',
          className: 'dt-button'
        }
      ],
      language: {
        search: '_INPUT_',
        searchPlaceholder: 'Filter results...',
        lengthMenu: 'Show _MENU_ entries',
        info: 'Showing _START_ to _END_ of _TOTAL_ entries',
        paginate: {
          first: '<i class="fa-solid fa-angles-left"></i>',
          previous: '<i class="fa-solid fa-angle-left"></i>',
          next: '<i class="fa-solid fa-angle-right"></i>',
          last: '<i class="fa-solid fa-angles-right"></i>'
        }
      },
      classes: {
        sTable: 'enterprise-table'
      }
    };

    const combinedOptions = {
      ...defaultOptions,
      ...options,
      buttons: options.buttons || defaultOptions.buttons
    };

    // Initialize DataTable using jQuery mapping if available, or load standard
    if (typeof $ !== 'undefined' && $.fn.DataTable) {
      return $(selector).DataTable(combinedOptions);
    }
    
    console.warn('DataTable.js or jQuery not loaded yet');
    return null;
  }
};

window.Tables = Tables;
