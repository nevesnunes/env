app.directive('dateInterval', ['$timeout', function(timeout) {
	return {
		templateUrl: 'all/directives/dateInterval.html',
		replace: true,
		restrict: 'AE',
		scope: {
			blockId: '@',
			isDisabled: '=?',
			isShown: '=?',
			startDate: '=',
			endDate: '='
		},
		link: function($scope, element, attrs) {
			$scope.isDisabled = $scope.isDisabled || false;
			$scope.isShown = $scope.isShown || false;
			
			timeout(function(scope) {
				var startDateSelector = "#" + attrs['blockId'] + "_StartDate";
				var endDateSelector = "#" + attrs['blockId'] + "_EndDate";

				jQuery(startDateSelector).datepicker({
					dateFormat : 'dd/mm/yy',
					changeMonth : true,
					changeYear : true,
					minDate : new Date(1000, 1, 1),
					onSelect : function(date) {
						var newStartDate = jQuery(startDateSelector).datepicker('getDate');
						var newEndDate = new Date();
						newEndDate.setDate(newStartDate.getDate() + 1);
						jQuery(endDateSelector).datepicker(
								'option', 'minDate', newEndDate);
						
						// This handler breaks AngularJS binding,
						// changes must be explicitly propagated
				        scope.startDate = jQuery.datepicker.formatDate('dd/mm/yy', newStartDate);
				        scope.$applyAsync();
					}
				});

				var date = jQuery(startDateSelector).datepicker('getDate');
				if (date)
					date.setDate(date.getDate() + 1);
				else if (scope.startDate)
					date.setDate(scope.startDate.getDate());

				jQuery(endDateSelector).datepicker({
					dateFormat : 'dd/mm/yy',
					changeMonth : true,
					changeYear : true,
					minDate : new Date(1000, 1, 1)
				});
				jQuery(endDateSelector).datepicker(
						'option', 'minDate', date);
			}, 0, true, $scope);
		}
	};
}]);

//filter by subdivision
app.filter('srcByDateInterval', function() {
	return function (arr, dates) {
		var startDate = dates[0];
		var endDate = dates[1];
		var start = startDate ? jQuery.datepicker.parseDate('dd/mm/yy', startDate) : undefined;
		var end = endDate ? jQuery.datepicker.parseDate('dd/mm/yy', endDate) : undefined;
		return arr.filter(function(el) {
			var date = new Date(el.timedate);
			var isStartOk = start ? (date >= start) : true; 
			var isEndOk = end ? (date <= end) : true; 
			return isStartOk && isEndOk;
		});
	};
});
